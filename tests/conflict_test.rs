#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use airlock::arbiter::{ChannelArbiter, ConflictError, ConflictPolicy};

#[derive(Deserialize, Debug, Default)]
struct StreamQuery {
    stream_id: Option<String>,
    force: Option<String>,
}

fn parse_force_flag(param: Option<&str>) -> bool {
    matches!(param, Some("1" | "true" | "yes" | "force"))
}

async fn handle_live_stream_endpoint(
    State(arbiter): State<Arc<ChannelArbiter>>,
    Query(query): Query<StreamQuery>,
) -> Response {
    let stream_id = query.stream_id.unwrap_or_else(|| "0".to_string());
    if stream_id.is_empty() || stream_id == "0" {
        return (StatusCode::BAD_REQUEST, "Invalid stream_id").into_response();
    }

    let force = parse_force_flag(query.force.as_deref());

    match arbiter.request_stream(&stream_id, force) {
        Ok(grant) => (
            StatusCode::OK,
            [("content-type", "video/mp2t")],
            format!(
                "Stream started: stream_id={}, subscribers={}, is_preemption={}",
                grant.stream_id, grant.subscribers, grant.is_preemption
            ),
        )
            .into_response(),
        Err(conflict) => conflict.to_response(),
    }
}

/// Unit test verifying multi-channel arbitration and preemption sequence:
/// 1. First client tunes to `ch1` -> Granted.
/// 2. Second client tunes to `ch1` -> Granted (multi-subscriber).
/// 3. Third client attempts `ch2` with `force=false` -> Rejected with ConflictError::StreamInUse.
/// 4. Fourth client attempts `ch2` with `force=true` -> Granted (preempts `ch1`).
#[test]
fn test_channel_arbiter_conflict_and_preemption_lifecycle() {
    let arbiter = ChannelArbiter::new(ConflictPolicy::RejectIfActive);

    // Initial state: idle
    assert_eq!(arbiter.active_stream(), None);
    assert_eq!(arbiter.active_subscribers(), 0);
    assert!(!arbiter.is_in_use());

    // 1. First client tunes to ch1 -> Granted
    let grant1 = arbiter
        .request_stream("ch1", false)
        .expect("Client 1 tune to ch1 should succeed");
    assert_eq!(grant1.stream_id(), "ch1");
    assert_eq!(grant1.subscribers(), 1);
    assert!(!grant1.is_preemption());
    assert!(grant1.previous_stream_id().is_none());
    assert_eq!(arbiter.active_stream().as_deref(), Some("ch1"));
    assert_eq!(arbiter.active_subscribers(), 1);
    assert!(arbiter.is_in_use());

    // 2. Second client tunes to ch1 -> Granted (multi-subscriber)
    let grant2 = arbiter
        .request_stream("ch1", false)
        .expect("Client 2 tune to ch1 should succeed");
    assert_eq!(grant2.stream_id(), "ch1");
    assert_eq!(grant2.subscribers(), 2);
    assert!(!grant2.is_preemption());
    assert!(grant2.is_shared());
    assert_eq!(arbiter.active_subscribers(), 2);

    // 3. Third client attempts ch2 with force=false -> Rejected with ConflictError::StreamInUse
    let conflict = arbiter
        .request_stream("ch2", false)
        .expect_err("Client 3 should be rejected with conflict");

    match &conflict {
        ConflictError::StreamInUse {
            active_stream_id,
            active_subscribers,
            started_at,
        } => {
            assert_eq!(active_stream_id, "ch1");
            assert_eq!(*active_subscribers, 2);
            assert!(started_at.elapsed() < Duration::from_secs(5));
        }
    }

    // Verify ConflictError display formatting
    let err_display = conflict.to_string();
    assert!(err_display.contains("Stream 'ch1' is currently active with 2 subscriber(s)"));

    // Verify ConflictError HTTP response mapping
    let http_response = conflict.to_response();
    assert_eq!(http_response.status(), StatusCode::CONFLICT);

    // Verify tuner state remains held by ch1 with 2 subscribers
    assert_eq!(arbiter.active_stream().as_deref(), Some("ch1"));
    assert_eq!(arbiter.active_subscribers(), 2);

    // 4. Fourth client attempts ch2 with force=true -> Granted (preempts ch1)
    let grant4 = arbiter
        .request_stream("ch2", true)
        .expect("Client 4 with force=true should preempt ch1");
    assert_eq!(grant4.stream_id(), "ch2");
    assert!(grant4.is_preemption());
    assert_eq!(grant4.previous_stream_id(), Some("ch1"));
    assert_eq!(grant4.subscribers(), 1);

    // Verify tuner state switched to ch2
    assert_eq!(arbiter.active_stream().as_deref(), Some("ch2"));
    assert_eq!(arbiter.active_subscribers(), 1);
}

/// End-to-end integration test verifying HTTP 409 Conflict JSON details:
/// - Client 1 (GET /api/stream/live?stream_id=ch1) -> HTTP 200 OK.
/// - Client 2 (GET /api/stream/live?stream_id=ch1) -> HTTP 200 OK.
/// - Client 3 (GET /api/stream/live?stream_id=ch2) -> HTTP 409 Conflict with JSON details:
///   {"error": "tuner_busy", "active_stream_id": "ch1", "subscribers": 2, "hint": "Pass ?force=1 to preempt"}
/// - Client 4 (GET /api/stream/live?stream_id=ch2&force=1) -> HTTP 200 OK.
#[tokio::test]
async fn test_http_conflict_response_and_force_preemption_integration() {
    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));

    let app = Router::new()
        .route("/api/stream/live", get(handle_live_stream_endpoint))
        .with_state(Arc::clone(&arbiter));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral TCP port");
    let local_addr: SocketAddr = listener.local_addr().expect("Failed to get local address");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Server failed to run");
    });

    let client = reqwest::Client::new();
    let base_url = format!("http://{local_addr}");

    // Client 1 requests ch1
    let resp1 = client
        .get(format!("{base_url}/api/stream/live?stream_id=ch1"))
        .send()
        .await
        .expect("Client 1 request failed");
    assert_eq!(resp1.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp1
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("video/mp2t")
    );
    assert_eq!(arbiter.active_subscribers(), 1);

    // Client 2 requests same ch1 (multi-subscriber fan-out)
    let resp2 = client
        .get(format!("{base_url}/api/stream/live?stream_id=ch1"))
        .send()
        .await
        .expect("Client 2 request failed");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
    assert_eq!(arbiter.active_subscribers(), 2);

    // Client 3 requests ch2 without force -> HTTP 409 Conflict
    let resp3 = client
        .get(format!("{base_url}/api/stream/live?stream_id=ch2"))
        .send()
        .await
        .expect("Client 3 request failed");
    assert_eq!(resp3.status(), reqwest::StatusCode::CONFLICT);

    let json_body: serde_json::Value = resp3
        .json()
        .await
        .expect("Failed to parse JSON response for HTTP 409");

    assert_eq!(json_body["error"], "tuner_busy");
    assert_eq!(json_body["active_stream_id"], "ch1");
    assert_eq!(json_body["subscribers"], 2);
    assert_eq!(json_body["hint"], "Pass ?force=1 to preempt");

    // Client 4 requests ch2 with ?force=1 -> HTTP 200 OK (preempts ch1)
    let resp4 = client
        .get(format!("{base_url}/api/stream/live?stream_id=ch2&force=1"))
        .send()
        .await
        .expect("Client 4 request failed");
    assert_eq!(resp4.status(), reqwest::StatusCode::OK);

    assert_eq!(arbiter.active_stream().as_deref(), Some("ch2"));
    assert_eq!(arbiter.active_subscribers(), 1);
}

/// Test verifying preemption behavior under `ConflictPolicy::Preempt`.
#[test]
fn test_preempt_policy_automatically_switches_channel() {
    let arbiter = ChannelArbiter::new(ConflictPolicy::Preempt);

    // Client 1 tunes to ch1
    let grant1 = arbiter
        .request_stream("ch1", false)
        .expect("Tune ch1 should succeed");
    assert_eq!(grant1.stream_id(), "ch1");
    assert_eq!(arbiter.active_subscribers(), 1);

    // Client 2 tunes to ch2 without force=true, but policy is Preempt
    let grant2 = arbiter
        .request_stream("ch2", false)
        .expect("Tune ch2 should preempt ch1 automatically under Preempt policy");
    assert_eq!(grant2.stream_id(), "ch2");
    assert!(grant2.is_preemption());
    assert_eq!(grant2.previous_stream_id(), Some("ch1"));
    assert_eq!(arbiter.active_stream().as_deref(), Some("ch2"));
    assert_eq!(arbiter.active_subscribers(), 1);
}

/// Test verifying subscriber release and clean handover when tuner is idle.
#[test]
fn test_subscriber_release_allows_idle_handover_without_preemption() {
    let arbiter = ChannelArbiter::new(ConflictPolicy::RejectIfActive);

    // Client 1 tunes to ch1
    arbiter
        .request_stream("ch1", false)
        .expect("Tune ch1 should succeed");
    assert_eq!(arbiter.active_subscribers(), 1);

    // Client 1 releases subscription
    let remaining = arbiter.release_subscriber("ch1");
    assert_eq!(remaining, 0);
    assert_eq!(arbiter.active_subscribers(), 0);

    // Client 2 tunes to ch2 with force=false -> Allowed because active subscribers == 0
    let grant2 = arbiter
        .request_stream("ch2", false)
        .expect("Tune ch2 should succeed because tuner has 0 active subscribers");
    assert_eq!(grant2.stream_id(), "ch2");
    assert!(!grant2.is_preemption());
    assert_eq!(arbiter.active_stream().as_deref(), Some("ch2"));
    assert_eq!(arbiter.active_subscribers(), 1);
}

/// Test verifying RAII subscriber guard drop behavior.
#[test]
fn test_arbiter_subscriber_guard_auto_release() {
    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));

    {
        let (_grant, guard) = arbiter
            .acquire_guard("ch100", false)
            .expect("Acquiring guard should succeed");
        assert_eq!(guard.stream_id(), "ch100");
        assert_eq!(arbiter.active_subscribers(), 1);
    } // guard dropped here

    assert_eq!(arbiter.active_subscribers(), 0);
}

/// Test verifying multi-threaded concurrent subscriber contention and race safety.
#[tokio::test]
async fn test_concurrent_multi_subscriber_race_safety() {
    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));
    let mut handles = Vec::new();

    // Spawn 20 tasks concurrently tuning to "espn_hd"
    for _ in 0..20 {
        let arb = Arc::clone(&arbiter);
        handles.push(tokio::spawn(async move {
            arb.request_stream_async("espn_hd", false).await
        }));
    }

    for handle in handles {
        let res = handle.await.expect("task join failed");
        assert!(res.is_ok());
    }

    assert_eq!(arbiter.active_stream().as_deref(), Some("espn_hd"));
    assert_eq!(arbiter.active_subscribers(), 20);

    // Attempting a different channel without force must be rejected with 20 subscribers
    let conflict = arbiter
        .request_stream("fox_sports", false)
        .expect_err("Should be rejected");
    match conflict {
        ConflictError::StreamInUse {
            active_stream_id,
            active_subscribers,
            ..
        } => {
            assert_eq!(active_stream_id, "espn_hd");
            assert_eq!(active_subscribers, 20);
        }
    }
}
