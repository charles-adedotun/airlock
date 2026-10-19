#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use clap::Parser;
use futures_util::Stream;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use airlock::arbiter::{ArbiterSubscriberGuard, ChannelArbiter, ConflictPolicy as ArbiterPolicy};
use airlock::config::{
    AirlockConfigFile, CliArgs, ConflictPolicy as ConfigConflictPolicy, load_config_with_fallback,
};
use airlock::engine::{CatalogSyncManager, HlsPlaylistGenerator, LineupManager, create_lineup_router};
use airlock::ingest::{LiveBroadcastHub, UpstreamHub};
use airlock::range::{HttpRange, parse_range_header, resolve_range};
use airlock::security::{SafePathGuard, create_hardened_http_client};
use airlock::signals::wait_for_shutdown_signal;
#[cfg(unix)]
use airlock::storage::posix_fadvise_dontneed_fd;
use airlock::storage::{QuotaConfig, SharedQuotaManager, check_host_memory_headroom};

#[derive(Clone)]
struct AppState {
    config: Arc<AirlockConfigFile>,
    cache_dir: PathBuf,
    quota_manager: SharedQuotaManager,
    broadcast_hub: Arc<LiveBroadcastHub>,
    arbiter: Arc<ChannelArbiter>,
    hls_generator: Arc<HlsPlaylistGenerator>,
    path_guard: Arc<SafePathGuard>,
    internal_client: reqwest::Client,
    outbound_client: reqwest::Client,
}

#[derive(Deserialize, Debug, Default)]
struct LiveStreamQuery {
    stream_id: Option<String>,
    #[serde(default)]
    force: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct StreamOptQuery {
    #[serde(default)]
    force: Option<String>,
}

#[derive(Deserialize, Debug)]
struct VodStreamQuery {
    stream_id: Option<String>,
    #[allow(dead_code)]
    kind: Option<String>,
    ext: Option<String>,
}

/// Stream wrapper holding an RAII `ArbiterSubscriberGuard`.
/// Automatically decrements the active arbiter subscriber count when the client disconnects.
struct ArbiterGuardedStream<S> {
    stream: S,
    _guard: ArbiterSubscriberGuard,
}

impl<S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin> Stream for ArbiterGuardedStream<S> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

async fn healthz_handler() -> impl IntoResponse {
    let memory_ok = check_host_memory_headroom();
    if memory_ok {
        (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "service": "airlock",
                "version": env!("CARGO_PKG_VERSION"),
                "status": "healthy",
                "memory_headroom_ok": true
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "service": "airlock",
                "version": env!("CARGO_PKG_VERSION"),
                "status": "degraded_low_host_memory",
                "memory_headroom_ok": false
            })),
        )
    }
}

async fn status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let usage = state.quota_manager.usage_info(&state.cache_dir).await.ok();
    Json(json!({
        "service": "airlock",
        "version": env!("CARGO_PKG_VERSION"),
        "upstream_provider": state.config.server.upstream,
        "catalog_upstream": state.config.server.catalog_upstream,
        "listen_addr": state.config.server.listen.to_string(),
        "storage": {
            "cache_dir": state.cache_dir.display().to_string(),
            "usage": usage,
            "max_storage_gb": state.config.storage.max_storage_gb,
            "min_disk_free_gb": state.config.storage.min_disk_free_gb
        },
        "sports_target_latency_sec": state.config.streaming.sports_latency_sec,
        "conflict_policy": state.config.streaming.conflict_policy.to_string(),
        "active_broadcast_sessions": state.broadcast_hub.active_sessions_count().await,
        "host_memory_headroom_ok": check_host_memory_headroom()
    }))
}

// Live Stream Handlers

fn clean_stream_id(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_suffix(".ts").unwrap_or(s);
    let s = s.strip_suffix(".m3u8").unwrap_or(s);
    let s = s.strip_suffix(".mp4").unwrap_or(s);
    s.to_string()
}

async fn handle_live_xtream(
    State(state): State<AppState>,
    Query(opt): Query<StreamOptQuery>,
    Path((_user, _pass, target)): Path<(String, String, String)>,
) -> Response {
    let stream_id = clean_stream_id(&target);
    let force = opt.force.as_deref() == Some("1") || opt.force.as_deref() == Some("true");
    serve_live_stream_internal(state, stream_id, force).await
}

async fn handle_live_query(
    State(state): State<AppState>,
    Query(q): Query<LiveStreamQuery>,
) -> Response {
    let stream_id = q.stream_id.unwrap_or_else(|| "0".into());
    let stream_id = clean_stream_id(&stream_id);
    let force = q.force.as_deref() == Some("1") || q.force.as_deref() == Some("true");
    serve_live_stream_internal(state, stream_id, force).await
}

async fn serve_live_stream_internal(state: AppState, stream_id: String, force: bool) -> Response {
    if stream_id.is_empty() || stream_id == "0" {
        return (StatusCode::BAD_REQUEST, "Invalid stream_id").into_response();
    }

    // Arbitration check
    let (_grant, guard) = match state.arbiter.acquire_guard(&stream_id, force) {
        Ok(g) => g,
        Err(conflict) => {
            return conflict.to_response();
        }
    };

    match state.broadcast_hub.subscribe(&stream_id).await {
        Ok(stream) => {
            let guarded = ArbiterGuardedStream {
                stream,
                _guard: guard,
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "video/mp2t")
                .header(header::CACHE_CONTROL, "no-store")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONNECTION, "close")
                .body(axum::body::Body::from_stream(guarded))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Stream response error").into_response()
                })
        }
        Err(err) => {
            tracing::warn!(stream_id = %stream_id, error = %err, "Live stream subscription failed");
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to connect to live stream: {err}"),
            )
                .into_response()
        }
    }
}

// In-Flight HLS Handlers

async fn handle_hls_playlist_xtream(
    State(state): State<AppState>,
    Path((_user, _pass, target)): Path<(String, String, String)>,
) -> Response {
    let stream_id = clean_stream_id(&target);
    serve_hls_playlist_internal(state, stream_id).await
}

async fn handle_hls_playlist_query(
    State(state): State<AppState>,
    Query(q): Query<LiveStreamQuery>,
) -> Response {
    let stream_id = q.stream_id.unwrap_or_else(|| "0".into());
    let stream_id = clean_stream_id(&stream_id);
    serve_hls_playlist_internal(state, stream_id).await
}

async fn serve_hls_playlist_internal(state: AppState, stream_id: String) -> Response {
    if stream_id.is_empty() || stream_id == "0" {
        return (StatusCode::BAD_REQUEST, "Invalid stream_id").into_response();
    }

    let base_uri = format!("/live/hls/proxy/{stream_id}");
    let playlist = match state.broadcast_hub.get_session(&stream_id).await {
        Some(session) => state
            .hls_generator
            .generate_from_ts_ring(&session.ts_ring, &base_uri)
            .unwrap_or_else(|_| state.hls_generator.generate_from_segments(&[])),
        None => state.hls_generator.generate_from_segments(&[]),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(axum::body::Body::from(playlist))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HLS playlist error").into_response())
}

async fn handle_hls_segment(
    State(state): State<AppState>,
    Path((stream_id, segment)): Path<(String, String)>,
) -> Response {
    let clean_id = clean_stream_id(&stream_id);
    let seq_str = segment
        .trim_start_matches("ring_seg_")
        .trim_end_matches(".ts");

    if let Ok(seq) = seq_str.parse::<u64>() {
        if let Some(session) = state.broadcast_hub.get_session(&clean_id).await {
            if let Ok((chunks, _)) = session.ts_ring.read_from(seq, 1) {
                if let Some(chunk) = chunks.into_iter().next() {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "video/mp2t")
                        .header(header::CACHE_CONTROL, "public, max-age=60")
                        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(axum::body::Body::from(chunk.data))
                        .unwrap_or_else(|_| {
                            (StatusCode::INTERNAL_SERVER_ERROR, "Segment error").into_response()
                        });
                }
            }
        }
    }

    (StatusCode::NOT_FOUND, "Segment not found or expired from ring buffer").into_response()
}

// VOD & Range Handlers

async fn handle_vod_xtream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((_user, _pass, target)): Path<(String, String, String)>,
) -> Response {
    let stream_id = clean_stream_id(&target);
    serve_vod_internal(state, headers, stream_id, "mp4").await
}

async fn handle_vod_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<VodStreamQuery>,
) -> Response {
    let stream_id = q.stream_id.unwrap_or_else(|| "0".into());
    let stream_id = clean_stream_id(&stream_id);
    let ext = q.ext.unwrap_or_else(|| "mp4".into());
    serve_vod_internal(state, headers, stream_id, &ext).await
}

async fn serve_vod_internal(
    state: AppState,
    headers: HeaderMap,
    stream_id: String,
    ext: &str,
) -> Response {
    if stream_id.is_empty() || stream_id == "0" {
        return (StatusCode::BAD_REQUEST, "Invalid stream_id").into_response();
    }

    // Check if the file is already cached locally on disk
    if let Ok(final_path) = state.path_guard.final_path_with_ext(&stream_id, ext) {
        if let Ok(metadata) = tokio::fs::metadata(&final_path).await {
            let total_size = metadata.len();
            let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());

            let http_range = match range_header {
                Some(r) => match parse_range_header(r) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        return (StatusCode::RANGE_NOT_SATISFIABLE, "Invalid range header")
                            .into_response();
                    }
                },
                None => HttpRange::Single {
                    start: 0,
                    end: None,
                },
            };

            let resolved = match resolve_range(&http_range, total_size) {
                Ok(r) => r,
                Err(_) => {
                    return (StatusCode::RANGE_NOT_SATISFIABLE, "Range not satisfiable")
                        .into_response();
                }
            };

            let start = resolved.start;
            let length = resolved.length();
            let _end = resolved.end;

            if let Ok(mut file) = tokio::fs::File::open(&final_path).await {
                use tokio::io::{AsyncReadExt, AsyncSeekExt};
                if file.seek(std::io::SeekFrom::Start(start)).await.is_ok() {
                    // Advise Linux kernel to drop page cache for cold video data using existing raw FD
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        let _ = posix_fadvise_dontneed_fd(file.as_raw_fd(), start as i64, length as i64);
                    }

                    let take_file = tokio_util::io::ReaderStream::new(file.take(length));
                    let content_range = resolved.content_range_value();

                    return Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header(header::CONTENT_TYPE, "video/mp4")
                        .header(header::ACCEPT_RANGES, "bytes")
                        .header(header::CONTENT_RANGE, content_range)
                        .header(header::CONTENT_LENGTH, length.to_string())
                        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(axum::body::Body::from_stream(take_file))
                        .unwrap_or_else(|_| {
                            (StatusCode::INTERNAL_SERVER_ERROR, "File range error").into_response()
                        });
                }
            }
        }
    }

    // Fallback: proxy upstream with Range header forwarding
    let upstream_base = state.config.server.upstream.trim_end_matches('/');
    let target_url = format!("{upstream_base}/movie/airlock/proxy/{stream_id}.{ext}");

    let mut req = state.outbound_client.get(&target_url);
    if let Some(r) = headers.get(header::RANGE) {
        req = req.header(header::RANGE, r);
    }

    match req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let mut builder = Response::builder().status(status);
            for (key, val) in resp.headers().iter() {
                if key != "transfer-encoding" {
                    builder = builder.header(key, val);
                }
            }
            builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            let stream = resp.bytes_stream();
            builder
                .body(axum::body::Body::from_stream(stream))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Proxy response error").into_response()
                })
        }
        Err(err) => {
            tracing::warn!(stream_id = %stream_id, error = %err, "Upstream VOD request failed");
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to proxy VOD stream: {err}"),
            )
                .into_response()
        }
    }
}

// Fallback Proxy to Python Catalog Backend (:8794)

async fn proxy_catalog_fallback(
    State(state): State<AppState>,
    req: Request,
) -> Response {
    let path = req.uri().path();
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let catalog_base = state.config.server.catalog_upstream.trim_end_matches('/');
    let target_url = format!("{catalog_base}{path}{query}");

    let method = req.method().clone();
    let headers = req.headers().clone();

    let mut proxy_req = state.internal_client.request(method, &target_url);
    for (name, value) in headers.iter() {
        if name != "host" && name != "connection" {
            proxy_req = proxy_req.header(name, value);
        }
    }

    match proxy_req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let mut builder = Response::builder().status(status);
            for (key, val) in resp.headers().iter() {
                if key != "transfer-encoding" {
                    builder = builder.header(key, val);
                }
            }
            builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            let stream = resp.bytes_stream();
            builder
                .body(axum::body::Body::from_stream(stream))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Proxy response error").into_response()
                })
        }
        Err(err) => {
            tracing::warn!(target = %target_url, error = %err, "Failed to proxy to catalog backend");
            (
                StatusCode::BAD_GATEWAY,
                format!(
                    "Catalog backend unreachable at {}: {err}",
                    state.config.server.catalog_upstream
                ),
            )
                .into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,airlock=debug".into()),
        )
        .init();

    let cli = CliArgs::parse();
    let config = load_config_with_fallback(cli.config.as_deref()).unwrap_or_default();
    let config = Arc::new(config.merged_with_cli(&cli));

    let cache_dir = config.storage.resolved_cache_dir();
    tokio::fs::create_dir_all(&cache_dir).await?;

    let max_bytes = config.storage.max_storage_gb.clamp(50, 200) * 1024 * 1024 * 1024;
    let min_free_disk_bytes = config.storage.min_disk_free_gb * 1024 * 1024 * 1024;

    let quota_config = QuotaConfig {
        min_cache_bytes: 50 * 1024 * 1024 * 1024,
        max_cache_bytes: max_bytes,
        emergency_disk_floor_bytes: min_free_disk_bytes,
    };
    let quota_manager = SharedQuotaManager::new(quota_config);
    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(300)));
    let path_guard = Arc::new(SafePathGuard::new(&cache_dir)?);

    let arbiter_policy = match config.streaming.conflict_policy {
        ConfigConflictPolicy::Reject => ArbiterPolicy::RejectIfActive,
        ConfigConflictPolicy::Preempt => ArbiterPolicy::Preempt,
    };
    let arbiter = Arc::new(ChannelArbiter::new(arbiter_policy));
    let hls_generator = Arc::new(HlsPlaylistGenerator::new());

    let internal_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let outbound_client = create_hardened_http_client(config.server.allow_private_upstream)?;

    let broadcast_hub = Arc::new(LiveBroadcastHub::new(
        Arc::clone(&upstream_hub),
        outbound_client.clone(),
        config.server.upstream.clone(),
        16 * 1024 * 1024,
    ));

    let lineup_manager = Arc::new(LineupManager::new(
        format!("http://{}", config.server.listen),
        "AIRLOCK001",
    ));
    let lineup_routes = create_lineup_router(Arc::clone(&lineup_manager));

    let (catalog_shutdown_tx, catalog_shutdown_rx) = tokio::sync::watch::channel(false);
    let catalog_sync = Arc::new(CatalogSyncManager::new(
        Arc::clone(&lineup_manager),
        internal_client.clone(),
        config.server.catalog_upstream.clone(),
    ));
    let _catalog_task = catalog_sync.spawn_periodic_sync(
        Duration::from_secs(6 * 3600),
        catalog_shutdown_rx,
    );

    let app_state = AppState {
        config: Arc::clone(&config),
        cache_dir: cache_dir.clone(),
        quota_manager,
        broadcast_hub,
        arbiter,
        hls_generator,
        path_guard,
        internal_client,
        outbound_client,
    };

    let app = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/api/healthz", get(healthz_handler))
        .route("/api/status", get(status_handler))
        // Raw TS Streaming routes
        .route("/live/:user/:pass/:target", get(handle_live_xtream))
        .route("/api/stream/live", get(handle_live_query))
        // Dynamic Sliding-Window HLS routes
        .route("/live/hls/:user/:pass/:target/index.m3u8", get(handle_hls_playlist_xtream))
        .route("/api/stream/hls/index.m3u8", get(handle_hls_playlist_query))
        .route("/live/hls/proxy/:stream_id/:segment", get(handle_hls_segment))
        .route("/movie/:user/:pass/:target", get(handle_vod_xtream))
        .route("/series/:user/:pass/:target", get(handle_vod_xtream))
        .route("/api/stream/vod", get(handle_vod_query))
        // Everything else proxies to Python catalog backend on :8794
        .fallback(proxy_catalog_fallback)
        .with_state(app_state)
        .merge(lineup_routes);

    info!(
        listen = %config.server.listen,
        upstream = %config.server.upstream,
        catalog_upstream = %config.server.catalog_upstream,
        cache_dir = %cache_dir.display(),
        max_storage_gb = config.storage.max_storage_gb,
        conflict_policy = %config.streaming.conflict_policy,
        allow_private_upstream = config.server.allow_private_upstream,
        "🚀 Airlock High-Throughput Streaming Engine initialized"
    );

    if !check_host_memory_headroom() {
        warn!("⚠️ Host memory headroom is currently below 1.5 GiB; write-leash may throttle");
    }

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_shutdown_signal().await;
            let _ = catalog_shutdown_tx.send(true);
        })
        .await?;

    Ok(())
}
