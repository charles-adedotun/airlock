//! Prometheus text metrics generation for Airlock streaming engine.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::path::Path;

use crate::arbiter::ChannelArbiter;
use crate::ingest::LiveBroadcastHub;
use crate::storage::SharedQuotaManager;

/// Render Prometheus text format (v0.0.4) metrics string.
pub async fn render_prometheus_metrics(
    quota_manager: &SharedQuotaManager,
    cache_dir: &Path,
    broadcast_hub: &LiveBroadcastHub,
    arbiter: &ChannelArbiter,
) -> String {
    let (max_storage_gb, _min_disk_free_gb) = quota_manager.current_limits().await;
    let usage_bytes = quota_manager
        .usage_info(cache_dir)
        .await
        .map(|u| u.cache_used_bytes)
        .unwrap_or(0);
    let active_sessions = broadcast_hub.active_sessions_count().await;
    let active_subs = arbiter.active_subscribers();

    let (cushion, jitter, stalls, bytes, active_stream_id) =
        if let Some(stream_id) = arbiter.active_stream() {
            if let Some((c, j, s, b)) = broadcast_hub.get_session_metrics(&stream_id).await {
                (c, j, s, b, Some(stream_id))
            } else {
                (3.5, 0.0, 0, 0, Some(stream_id))
            }
        } else {
            (3.5, 0.0, 0, 0, None)
        };

    let mut m = String::with_capacity(1024);
    m.push_str(
        "# HELP airlock_active_broadcast_sessions Number of active live broadcast sessions\n",
    );
    m.push_str("# TYPE airlock_active_broadcast_sessions gauge\n");
    m.push_str(&format!(
        "airlock_active_broadcast_sessions {active_sessions}\n"
    ));

    m.push_str("# HELP airlock_active_subscribers Number of active downstream subscribers\n");
    m.push_str("# TYPE airlock_active_subscribers gauge\n");
    m.push_str(&format!("airlock_active_subscribers {active_subs}\n"));

    m.push_str("# HELP airlock_storage_bytes Current storage usage in bytes\n");
    m.push_str("# TYPE airlock_storage_bytes gauge\n");
    m.push_str(&format!("airlock_storage_bytes {usage_bytes}\n"));

    m.push_str("# HELP airlock_storage_max_bytes Max allowed storage in bytes\n");
    m.push_str("# TYPE airlock_storage_max_bytes gauge\n");
    m.push_str(&format!(
        "airlock_storage_max_bytes {}\n",
        max_storage_gb * 1024 * 1024 * 1024
    ));

    m.push_str("# HELP airlock_reservoir_cushion_sec Recommended pre-roll cushion in seconds\n");
    m.push_str("# TYPE airlock_reservoir_cushion_sec gauge\n");
    if let Some(ref stream_id) = active_stream_id {
        m.push_str(&format!(
            "airlock_reservoir_cushion_sec{{stream_id=\"{stream_id}\"}} {cushion:.2}\n"
        ));
    } else {
        m.push_str(&format!("airlock_reservoir_cushion_sec {cushion:.2}\n"));
    }

    m.push_str("# HELP airlock_upstream_jitter_ms Measured upstream packet jitter EMA in ms\n");
    m.push_str("# TYPE airlock_upstream_jitter_ms gauge\n");
    if let Some(ref stream_id) = active_stream_id {
        m.push_str(&format!(
            "airlock_upstream_jitter_ms{{stream_id=\"{stream_id}\"}} {jitter:.2}\n"
        ));
    } else {
        m.push_str(&format!("airlock_upstream_jitter_ms {jitter:.2}\n"));
    }

    m.push_str("# HELP airlock_stalls_absorbed_total Upstream stalls successfully absorbed\n");
    m.push_str("# TYPE airlock_stalls_absorbed_total counter\n");
    if let Some(ref stream_id) = active_stream_id {
        m.push_str(&format!(
            "airlock_stalls_absorbed_total{{stream_id=\"{stream_id}\"}} {stalls}\n"
        ));
    } else {
        m.push_str(&format!("airlock_stalls_absorbed_total {stalls}\n"));
    }

    m.push_str("# HELP airlock_ingested_bytes_total Total bytes ingested for stream\n");
    m.push_str("# TYPE airlock_ingested_bytes_total counter\n");
    if let Some(ref stream_id) = active_stream_id {
        m.push_str(&format!(
            "airlock_ingested_bytes_total{{stream_id=\"{stream_id}\"}} {bytes}\n"
        ));
    } else {
        m.push_str(&format!("airlock_ingested_bytes_total {bytes}\n"));
    }

    m
}

/// Create an HTTP Response with Content-Type text/plain; version=0.0.4.
pub async fn render_metrics_response(
    quota_manager: &SharedQuotaManager,
    cache_dir: &Path,
    broadcast_hub: &LiveBroadcastHub,
    arbiter: &ChannelArbiter,
) -> Response {
    let body = render_prometheus_metrics(quota_manager, cache_dir, broadcast_hub, arbiter).await;
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Metrics error").into_response())
}
