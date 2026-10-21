use airlock::ingest::{LiveBroadcastHub, UpstreamHub};
use futures_util::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_broadcast_fan_out_guarantees_single_upstream_socket() {
    let mock_server = MockServer::start().await;

    // Upstream sends 188-byte TS dummy chunk
    let mut dummy_ts = vec![0x47];
    dummy_ts.resize(188 * 5, 0);

    Mock::given(method("GET"))
        .and(path("/live/airlock/proxy/ch101.ts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(dummy_ts)
                .insert_header("content-type", "video/mp2t"),
        )
        .expect(1) // CRITICAL: Exactly 1 upstream request despite multiple concurrent clients!
        .mount(&mock_server)
        .await;

    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(50)));
    let http_client = reqwest::Client::new();
    let hub = Arc::new(LiveBroadcastHub::new(
        upstream_hub,
        http_client,
        mock_server.uri(),
        1024 * 1024,
    ));

    // Client 1 subscribes
    let mut sub1 = hub.subscribe("ch101").await.expect("Client 1 subscribe ok");
    assert_eq!(hub.subscribers_count("ch101").await, 1);
    assert_eq!(hub.active_sessions_count().await, 1);

    // Client 2 subscribes to the SAME channel
    let mut sub2 = hub.subscribe("ch101").await.expect("Client 2 subscribe ok");
    assert_eq!(hub.subscribers_count("ch101").await, 2);
    // Still exactly 1 active session!
    assert_eq!(hub.active_sessions_count().await, 1);

    // Both subscribers receive stream chunks
    let chunk1 = tokio::time::timeout(Duration::from_secs(1), sub1.next())
        .await
        .expect("sub1 not timed out")
        .expect("sub1 got item")
        .expect("sub1 chunk ok");
    assert!(!chunk1.is_empty());

    let chunk2 = tokio::time::timeout(Duration::from_secs(1), sub2.next())
        .await
        .expect("sub2 not timed out")
        .expect("sub2 got item")
        .expect("sub2 chunk ok");
    assert!(!chunk2.is_empty());

    // Client 1 drops
    drop(sub1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hub.subscribers_count("ch101").await, 1);

    // Client 2 drops
    drop(sub2);
    // Grace period is 1500ms, wait 1700ms for debounced cleanup
    tokio::time::sleep(Duration::from_millis(1700)).await;
    assert_eq!(hub.subscribers_count("ch101").await, 0);
    assert_eq!(hub.active_sessions_count().await, 0);
}

#[tokio::test]
async fn test_broadcast_uses_configured_credentials() {
    let mock_server = MockServer::start().await;

    // Upstream sends 188-byte TS dummy chunk
    let mut dummy_ts = vec![0x47];
    dummy_ts.resize(188 * 5, 0);

    // WireMock expects configured credentials in URL path:
    // /live/custom_user_123/custom_pass_xyz/stream99.ts
    Mock::given(method("GET"))
        .and(path("/live/custom_user_123/custom_pass_xyz/stream99.ts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(dummy_ts)
                .insert_header("content-type", "video/mp2t"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(50)));
    let http_client = reqwest::Client::new();
    let hub = Arc::new(LiveBroadcastHub::with_credentials(
        upstream_hub,
        http_client,
        mock_server.uri(),
        1024 * 1024,
        Some(airlock::security::RedactedString::new("custom_user_123")),
        Some(airlock::security::RedactedString::new("custom_pass_xyz")),
    ));

    let mut sub = hub.subscribe("stream99").await.expect("subscribe succeeds");
    let chunk = tokio::time::timeout(Duration::from_secs(1), sub.next())
        .await
        .expect("chunk not timed out")
        .expect("got chunk")
        .expect("chunk ok");
    assert!(!chunk.is_empty());
}
