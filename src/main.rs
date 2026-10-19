#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use airlock::engine::{LineupManager, create_lineup_router};
use airlock::ingest::UpstreamHub;
use airlock::range::{HttpRange, parse_range_header, resolve_range};
use airlock::security::SafePathGuard;
use airlock::storage::{
    QuotaConfig, SharedQuotaManager, check_host_memory_headroom, posix_fadvise_dontneed,
};

#[derive(Parser, Debug)]
#[command(
    name = "airlock",
    about = "High-Throughput Read-Ahead Streaming Proxy, Jitter Shield & Single-Upstream Arbiter",
    version
)]
struct Args {
    /// Bind address for the HTTP streaming and control server
    #[arg(short, long, env = "AIRLOCK_LISTEN", default_value = "0.0.0.0:8795")]
    listen: SocketAddr,

    /// Target upstream IPTV / media provider base URL
    #[arg(
        short,
        long,
        env = "AIRLOCK_UPSTREAM",
        default_value = "http://line.ottcst.org"
    )]
    upstream: String,

    /// Internal Python catalog & metadata service base URL
    #[arg(
        long,
        env = "AIRLOCK_CATALOG_UPSTREAM",
        default_value = "http://127.0.0.1:8794"
    )]
    catalog_upstream: String,

    /// Root directory for the rolling DVR and VOD cache
    #[arg(short, long, env = "AIRLOCK_CACHE_DIR")]
    cache_dir: Option<PathBuf>,

    /// Maximum rolling storage quota in gigabytes (50 to 200 GB)
    #[arg(long, env = "AIRLOCK_MAX_STORAGE_GB", default_value_t = 100)]
    max_storage_gb: u64,

    /// Minimum emergency free disk space floor in gigabytes
    #[arg(long, env = "AIRLOCK_MIN_DISK_FREE_GB", default_value_t = 10)]
    min_disk_free_gb: u64,

    /// Target buffer latency for live sports in seconds
    #[arg(long, env = "AIRLOCK_SPORTS_LATENCY_SEC", default_value_t = 2.0)]
    sports_latency_sec: f64,
}

#[derive(Clone)]
struct AppState {
    args: Arc<Args>,
    cache_dir: PathBuf,
    quota_manager: SharedQuotaManager,
    upstream_hub: Arc<UpstreamHub>,
    path_guard: Arc<SafePathGuard>,
    internal_client: reqwest::Client,
    outbound_client: reqwest::Client,
}

#[derive(Deserialize, Debug)]
struct LiveStreamQuery {
    stream_id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct VodStreamQuery {
    stream_id: Option<String>,
    #[allow(dead_code)]
    kind: Option<String>,
    ext: Option<String>,
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
        "upstream_provider": state.args.upstream,
        "catalog_upstream": state.args.catalog_upstream,
        "listen_addr": state.args.listen.to_string(),
        "storage": {
            "cache_dir": state.cache_dir.display().to_string(),
            "usage": usage,
            "max_storage_gb": state.args.max_storage_gb,
            "min_disk_free_gb": state.args.min_disk_free_gb
        },
        "sports_target_latency_sec": state.args.sports_latency_sec,
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
    Path((_user, _pass, target)): Path<(String, String, String)>,
) -> Response {
    let stream_id = clean_stream_id(&target);
    serve_live_stream_internal(state, stream_id).await
}

async fn handle_live_query(
    State(state): State<AppState>,
    Query(q): Query<LiveStreamQuery>,
) -> Response {
    let stream_id = q.stream_id.unwrap_or_else(|| "0".into());
    let stream_id = clean_stream_id(&stream_id);
    serve_live_stream_internal(state, stream_id).await
}

async fn serve_live_stream_internal(state: AppState, stream_id: String) -> Response {
    if stream_id.is_empty() || stream_id == "0" {
        return (StatusCode::BAD_REQUEST, "Invalid stream_id").into_response();
    }

    if let Err(err) = state.upstream_hub.switch_stream(&stream_id).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!("Upstream arbiter busy: {err}"),
        )
            .into_response();
    }

    let upstream_base = state.args.upstream.trim_end_matches('/');
    let target_url = format!("{upstream_base}/live/airlock/proxy/{stream_id}.ts");

    let hub = Arc::clone(&state.upstream_hub);
    let sid = stream_id.clone();

    match state.outbound_client.get(&target_url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                hub.release(&sid).await;
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Upstream error: HTTP {}", resp.status()),
                )
                    .into_response();
            }

            let stream = resp.bytes_stream().map(move |chunk_res| {
                chunk_res.map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionReset, e))
            });

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "video/mp2t")
                .header(header::CACHE_CONTROL, "no-store")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONNECTION, "close")
                .body(axum::body::Body::from_stream(stream))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Stream response error").into_response()
                })
        }
        Err(err) => {
            hub.release(&sid).await;
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to connect to upstream: {err}"),
            )
                .into_response()
        }
    }
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

    let final_path = match state.path_guard.final_path_with_ext(&stream_id, ext) {
        Ok(p) => p,
        Err(err) => {
            return (
                StatusCode::FORBIDDEN,
                format!("Path traversal blocked: {err}"),
            )
                .into_response();
        }
    };

    // If fully cached on NVMe rolling DVR, serve locally with zero network I/O
    if final_path.is_file() {
        if let Ok(metadata) = tokio::fs::metadata(&final_path).await {
            let total_size = metadata.len();
            let range_hdr = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
            let http_range = match range_hdr {
                Some(hdr) => match parse_range_header(hdr) {
                    Ok(r) => r,
                    Err(_) => {
                        return (StatusCode::RANGE_NOT_SATISFIABLE, "Invalid range")
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
                    let take_file = tokio_util::io::ReaderStream::new(file.take(length));
                    let content_range = resolved.content_range_value();

                    // Advise Linux kernel to drop page cache for cold video data
                    if let Ok(std_f) = std::fs::File::open(&final_path) {
                        let _ = posix_fadvise_dontneed(&std_f, start as i64, length as i64);
                    }

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
    let upstream_base = state.args.upstream.trim_end_matches('/');
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
                    (StatusCode::INTERNAL_SERVER_ERROR, "Stream response error").into_response()
                })
        }
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("Upstream VOD error: {err}"),
        )
            .into_response(),
    }
}

// Transparent Reverse Proxy to Python Catalog Backend (:8794)

async fn proxy_catalog_fallback(State(state): State<AppState>, req: Request) -> Response {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_url = format!(
        "{}{}",
        state.args.catalog_upstream.trim_end_matches('/'),
        path_and_query
    );
    let method = req.method().clone();
    let headers = req.headers().clone();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid request body: {err}"),
            )
                .into_response();
        }
    };

    let mut proxy_req = state.internal_client.request(method, &target_url);
    for (key, val) in headers.iter() {
        if key != "host" && key != "content-length" {
            proxy_req = proxy_req.header(key, val);
        }
    }
    if !body_bytes.is_empty() {
        proxy_req = proxy_req.body(body_bytes);
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
                    state.args.catalog_upstream
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

    let args = Arc::new(Args::parse());

    let cache_dir = args.cache_dir.clone().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home)
            .join(".cache")
            .join("airlock")
            .join("media")
    });

    tokio::fs::create_dir_all(&cache_dir).await?;

    let max_bytes = args.max_storage_gb.clamp(50, 200) * 1024 * 1024 * 1024;
    let min_free_disk_bytes = args.min_disk_free_gb * 1024 * 1024 * 1024;

    let quota_config = QuotaConfig {
        min_cache_bytes: 50 * 1024 * 1024 * 1024,
        max_cache_bytes: max_bytes,
        emergency_disk_floor_bytes: min_free_disk_bytes,
    };
    let quota_manager = SharedQuotaManager::new(quota_config);
    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(300)));
    let path_guard = Arc::new(SafePathGuard::new(&cache_dir)?);

    let internal_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let outbound_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    let lineup_manager = Arc::new(LineupManager::new(
        format!("http://{}", args.listen),
        "AIRLOCK001",
    ));
    let lineup_routes = create_lineup_router(lineup_manager);

    let app_state = AppState {
        args: Arc::clone(&args),
        cache_dir: cache_dir.clone(),
        quota_manager,
        upstream_hub,
        path_guard,
        internal_client,
        outbound_client,
    };

    let app = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/api/healthz", get(healthz_handler))
        .route("/api/status", get(status_handler))
        // Streaming routes
        .route("/live/:user/:pass/:target", get(handle_live_xtream))
        .route("/api/stream/live", get(handle_live_query))
        .route("/movie/:user/:pass/:target", get(handle_vod_xtream))
        .route("/series/:user/:pass/:target", get(handle_vod_xtream))
        .route("/api/stream/vod", get(handle_vod_query))
        // Everything else proxies to Python catalog backend on :8794
        .fallback(proxy_catalog_fallback)
        .with_state(app_state)
        .merge(lineup_routes);

    info!(
        listen = %args.listen,
        upstream = %args.upstream,
        catalog_upstream = %args.catalog_upstream,
        cache_dir = %cache_dir.display(),
        max_storage_gb = args.max_storage_gb,
        "🚀 Airlock High-Throughput Streaming Engine initialized"
    );

    if !check_host_memory_headroom() {
        warn!("⚠️ Host memory headroom is currently below 1.5 GiB; write-leash may throttle");
    }

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if let Err(err) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %err, "Failed to listen for shutdown signal");
            }
            info!("Shutting down Airlock streaming daemon...");
        })
        .await?;

    Ok(())
}
