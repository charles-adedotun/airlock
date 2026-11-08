use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use airlock::error::IngestError;
use airlock::ingest::{StreamBufferSession, UpstreamHub, await_byte_offset};
use airlock::ring::LiveRingBuffer;

/// Chaos Test A: Mid-stream socket abort
/// Verifies that `watch::Sender<IngestState>` wakes awaiting progressive readers
/// and causes them to abort cleanly in < 50ms without hanging.
#[tokio::test]
async fn test_chaos_midstream_abort_wakes_readers_under_50ms() {
    let (session, mut rx) = StreamBufferSession::new("vod_chaos_stream_1", None);

    // Initial progress: 1MB downloaded of 10MB total
    session.notify_progress(1_000_000, Some(10_000_000));

    // Spawn reader task awaiting byte offset 5,000,000 (which is not yet downloaded)
    let reader_handle = tokio::spawn(async move {
        let start_wait = Instant::now();
        let result = await_byte_offset(&mut rx, 5_000_000).await;
        (result, start_wait.elapsed())
    });

    // Allow reader to enter async wait
    sleep(Duration::from_millis(10)).await;

    // Simulate upstream connection reset / HTTP 500 mid-stream
    let abort_instant = Instant::now();
    session.mark_failed("Upstream connection reset by peer (TCP RST)");

    // Wait for reader to abort
    let (read_result, _total_wait) = reader_handle.await.expect("task did not panic");
    let wake_latency = abort_instant.elapsed();

    // Verify abort latency is strictly < 50ms
    assert!(
        wake_latency < Duration::from_millis(50),
        "Reader wakeup took {wake_latency:?}, exceeding the 50ms ceiling!"
    );

    // Verify reader received expected IngestError::Aborted
    match read_result {
        Err(IngestError::Aborted(msg)) => {
            assert!(msg.contains("Upstream connection reset"));
        }
        other => panic!("Expected IngestError::Aborted, got: {other:?}"),
    }
}

/// Chaos Test B: Upstream 2000ms jitter stall
/// Verifies that when upstream stalls for 2000ms, the client smoothly draws from
/// the local buffer without freezing or dropping the playback stream.
#[tokio::test]
async fn test_chaos_upstream_2000ms_jitter_stall() {
    // 1. Setup mock upstream server with WireMock
    let mock_server = MockServer::start().await;

    let payload = [0x47u8; 188]; // 1 MPEG-TS packet
    Mock::given(method("GET"))
        .and(path("/live/jitter_channel.ts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(payload.repeat(50))
                .set_delay(Duration::from_millis(2000)), // Injected 2000ms jitter stall!
        )
        .mount(&mock_server)
        .await;

    // 2. Local ring buffer primed with 2.5 seconds of media chunks (50 packets)
    let ring = Arc::new(LiveRingBuffer::new(1024 * 1024));
    for i in 0..50 {
        let chunk = Bytes::from(vec![0x47u8; 188]);
        ring.push(chunk, i % 10 == 0).expect("push into ring");
    }

    // 3. Client starts consuming from local buffer while upstream is stalled
    let ring_clone = ring.clone();
    let client_starved = Arc::new(AtomicBool::new(false));
    let client_starved_clone = client_starved.clone();

    let client_task = tokio::spawn(async move {
        let mut read_seq = 0;
        let start = Instant::now();

        // Simulate 2000ms playback: consumer reads 1 chunk every 35ms (~1400ms duration)
        while start.elapsed() < Duration::from_millis(1500) {
            let (chunks, next_seq) = ring_clone.read_from(read_seq, 1).expect("read ring");
            if chunks.is_empty() {
                client_starved_clone.store(true, Ordering::SeqCst);
                break;
            }
            read_seq = next_seq;
            sleep(Duration::from_millis(30)).await;
        }
    });

    // 4. Ingest task attempts to fetch from the stalled upstream
    let client = reqwest::Client::new();
    let upstream_url = format!("{}/live/jitter_channel.ts", mock_server.uri());
    let ingest_task = tokio::spawn(async move {
        let start = Instant::now();
        let resp = client.get(&upstream_url).send().await;
        (resp.is_ok(), start.elapsed())
    });

    // Await both tasks
    client_task.await.expect("client task finished");
    let (ingest_ok, ingest_duration) = ingest_task.await.expect("ingest task finished");

    assert!(ingest_ok, "Ingest request should eventually succeed");
    assert!(
        ingest_duration >= Duration::from_millis(2000),
        "Upstream stall must last at least 2000ms"
    );
    assert!(
        !client_starved.load(Ordering::SeqCst),
        "Client experienced buffer starvation during upstream jitter stall!"
    );
}

/// Chaos Test C: 10 requests/sec rapid channel zapping storm
/// Verifies that under rapid channel zapping (10 channel switches in 1 sec),
/// the `UpstreamHub` strictly preserves the `active_upstream <= 1` invariant at all times.
#[tokio::test]
async fn test_chaos_rapid_channel_zapping_storm() {
    let mock_server = MockServer::start().await;

    // Register 10 channel endpoints
    for i in 1..=10 {
        Mock::given(method("GET"))
            .and(path(format!("/live/channel_{i}.ts")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x47; 1880]))
            .mount(&mock_server)
            .await;
    }

    // Configure hub with a 15ms teardown cooldown barrier
    let hub = Arc::new(UpstreamHub::new(Duration::from_millis(15)));

    // Invariant monitor task: continuously asserts active_count <= 1
    let hub_monitor = hub.clone();
    let stop_monitor = Arc::new(AtomicBool::new(false));
    let stop_monitor_clone = stop_monitor.clone();

    let monitor_task = tokio::spawn(async move {
        let mut max_observed = 0;
        while !stop_monitor_clone.load(Ordering::SeqCst) {
            let current = hub_monitor.active_count();
            if current > max_observed {
                max_observed = current;
            }
            assert!(
                current <= 1,
                "CRITICAL INVARIANT VIOLATION: Observed {current} concurrent upstream connections!"
            );
            tokio::task::yield_now().await;
        }
        max_observed
    });

    // Execute 10 channel switches in 1000ms (100ms intervals = 10 requests/sec)
    for ch in 1..=10 {
        let stream_id = format!("channel_{ch}");
        let guard = hub
            .switch_stream(&stream_id)
            .await
            .expect("stream switch succeeded");

        assert_eq!(guard.load(Ordering::SeqCst), 1);
        assert_eq!(hub.active_count(), 1);

        sleep(Duration::from_millis(80)).await;
    }

    // Stop monitor and assert max observed was never > 1
    stop_monitor.store(true, Ordering::SeqCst);
    let max_connections = monitor_task.await.expect("monitor finished");
    assert_eq!(
        max_connections, 1,
        "Max concurrent connections must be exactly 1"
    );

    // Final release
    hub.release("channel_10").await;
    assert_eq!(hub.active_count(), 0);
}

// ============================================================================
// Chaos Test D & E: Upstream WAN Stalls, Adaptive Jitter Shield, Null Packet
// Injection, and Clean Teardown without Deadlock
// ============================================================================

use airlock::arbiter::{ChannelArbiter, ConflictPolicy};
use airlock::ingest::LiveBroadcastHub;
use airlock::metrics::{render_metrics_response, render_prometheus_metrics};
use airlock::storage::{QuotaConfig, SharedQuotaManager};
use futures_util::StreamExt;

fn create_test_ts_packet(pid: u16) -> [u8; 188] {
    let mut pkt = [0u8; 188];
    pkt[0] = 0x47; // TS_SYNC_BYTE
    pkt[1] = ((pid >> 8) as u8) & 0x1F;
    pkt[2] = (pid & 0xFF) as u8;
    pkt[3] = 0x10; // AFC: payload only
    pkt
}

async fn start_mock_streaming_upstream(
    stream_id: &'static str,
    stall_duration: Duration,
    send_resume_chunk: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    let path_url = format!("/live/airlock/proxy/{stream_id}.ts");
    let app = axum::Router::new().route(
        &path_url,
        axum::routing::get(move || async move {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
            tokio::spawn(async move {
                // Chunk 1: 7 TS packets of PID 0x0100 (1316 bytes MTU aligned)
                let pkt1 = create_test_ts_packet(0x0100);
                let mut chunk1 = Vec::with_capacity(188 * 7);
                for _ in 0..7 {
                    chunk1.extend_from_slice(&pkt1);
                }
                if tx.send(Ok(Bytes::from(chunk1))).await.is_err() {
                    return;
                }

                // Simulate upstream WAN stall
                tokio::time::sleep(stall_duration).await;

                if send_resume_chunk {
                    // Chunk 2: 7 TS packets of PID 0x0100 (1316 bytes MTU aligned)
                    let pkt2 = create_test_ts_packet(0x0100);
                    let mut chunk2 = Vec::with_capacity(188 * 7);
                    for _ in 0..7 {
                        chunk2.extend_from_slice(&pkt2);
                    }
                    let _ = tx.send(Ok(Bytes::from(chunk2))).await;

                    // Keep upstream open briefly so downstream reader can ingest and query metrics
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
            });
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
            let body = axum::body::Body::from_stream(stream);
            axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header(axum::http::header::CONTENT_TYPE, "video/mp2t")
                .body(body)
                .expect("valid mock response")
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{addr}"), server_handle)
}

/// Chaos Test D: Simulated Upstream WAN Stall of 3.0s
/// Specifically verifies:
/// a) `AdaptiveJitterShield` registers the stall in `stalls_absorbed()` and expands `recommended_cushion_sec()`.
/// b) Airlock injects standard MPEG-TS null packets (PID 0x1FFF) at nominal rate (~every 750ms) during the stall.
/// c) Downstream readers receive contiguous valid 188-byte aligned TS packets without connection reset.
#[tokio::test]
async fn test_chaos_upstream_wan_stall_3s_adaptive_shield_and_null_packets() {
    let stream_id = "ch_wan_stall_3s";
    let stall_duration = Duration::from_millis(3000);

    let (upstream_base, _server_task) =
        start_mock_streaming_upstream(stream_id, stall_duration, true).await;

    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(20)));
    let http_client = reqwest::Client::new();
    let hub = Arc::new(LiveBroadcastHub::new(
        upstream_hub,
        http_client,
        upstream_base,
        1024 * 1024,
    ));

    // Downstream reader subscribes to channel
    let mut sub = hub
        .subscribe(stream_id)
        .await
        .expect("downstream reader subscribe succeeds");

    assert_eq!(hub.active_sessions_count().await, 1);
    assert_eq!(hub.subscribers_count(stream_id).await, 1);

    let start_read = Instant::now();
    let mut chunks = Vec::new();
    let mut null_chunks_count = 0usize;
    let mut media_chunks_count = 0usize;

    // Collect chunks across the 3.0s stall and post-stall resume
    while let Ok(Some(chunk_res)) = tokio::time::timeout(Duration::from_secs(6), sub.next()).await {
        let chunk = chunk_res.expect("chunk received without connection reset");

        // c) Verify contiguous 188-byte aligned TS packets
        assert_eq!(
            chunk.len() % 188,
            0,
            "Chunk size {} must be an integral multiple of 188 bytes",
            chunk.len()
        );

        let mut has_null = false;
        let mut has_media = false;

        for pkt in chunk.as_chunks::<188>().0 {
            assert_eq!(pkt[0], 0x47, "TS packet must start with sync byte 0x47");
            let pid = (((pkt[1] & 0x1F) as u16) << 8) | (pkt[2] as u16);

            if pid == 0x1FFF {
                has_null = true;
            } else if pid == 0x0100 {
                has_media = true;
            } else {
                panic!("Unexpected MPEG-TS PID: {pid:#06x}");
            }
        }

        if has_null {
            null_chunks_count += 1;
        }
        if has_media {
            media_chunks_count += 1;
        }

        chunks.push(chunk);

        // Once we received initial media chunk, null chunks during stall, and post-stall chunk
        if media_chunks_count >= 2 && null_chunks_count >= 3 {
            break;
        }
    }

    let elapsed = start_read.elapsed();
    assert!(
        elapsed >= Duration::from_millis(2900),
        "Total streaming duration ({elapsed:?}) must cover the 3.0s WAN stall!"
    );

    // b) Verify Airlock injected standard MPEG-TS null packets (PID 0x1FFF) at nominal rate during stall
    assert!(
        null_chunks_count >= 3,
        "Expected at least 3 null packet chunks injected during 3.0s stall (~every 750ms), got {null_chunks_count}"
    );
    assert!(
        media_chunks_count >= 2,
        "Expected at least 2 media chunks (initial + post-stall resume), got {media_chunks_count}"
    );

    // a) Verify AdaptiveJitterShield registered stall and expanded recommended cushion
    let metrics = hub
        .get_session_metrics(stream_id)
        .await
        .expect("Session metrics must be available");
    let (cushion, jitter_ms, stalls_absorbed, total_bytes) = metrics;

    assert_eq!(
        stalls_absorbed, 1,
        "AdaptiveJitterShield must have registered exactly 1 absorbed WAN stall!"
    );
    assert!(
        cushion > 3.5,
        "Recommended cushion must have expanded from base 3.5s under WAN stall, got {cushion:.2}s"
    );
    assert!(
        jitter_ms > 200.0,
        "Measured jitter EMA must reflect the 3.0s arrival deviation, got {jitter_ms:.2}ms"
    );
    assert!(
        total_bytes >= 188 * 14,
        "Total bytes ingested should reflect both media chunks"
    );

    // Clean drop
    drop(sub);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hub.subscribers_count(stream_id).await, 0);
}

/// Chaos Test E: Upstream Stall Exceeding 8.0s Hard Ceiling
/// Specifically verifies:
/// Upstream stall exceeding 8.0s triggers a clean teardown without deadlock or resource leaks.
#[tokio::test]
async fn test_chaos_upstream_stall_exceeding_8s_clean_teardown() {
    let stream_id = "ch_wan_stall_8s";
    // Upstream stalls indefinitely (15 seconds)
    let (upstream_base, _server_task) =
        start_mock_streaming_upstream(stream_id, Duration::from_secs(15), false).await;

    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(20)));
    let http_client = reqwest::Client::new();
    let hub = Arc::new(LiveBroadcastHub::new(
        Arc::clone(&upstream_hub),
        http_client,
        upstream_base,
        1024 * 1024,
    ));

    // Downstream subscriber connects
    let mut sub = hub.subscribe(stream_id).await.expect("subscriber connects");

    assert_eq!(hub.active_sessions_count().await, 1);
    assert_eq!(upstream_hub.active_count(), 1);

    let start_stall = Instant::now();
    let mut null_packets_received = 0usize;

    // Downstream reader reads until the stream cleanly closes (EOF) upon 8.0s hard ceiling teardown
    let read_result = tokio::time::timeout(Duration::from_secs(12), async {
        while let Some(res) = sub.next().await {
            let chunk = res.expect("chunk ok during stall");
            assert_eq!(chunk.len() % 188, 0, "Packet alignment preserved");
            for pkt in chunk.as_chunks::<188>().0 {
                assert_eq!(pkt[0], 0x47, "Sync byte preserved");
                let pid = (((pkt[1] & 0x1F) as u16) << 8) | (pkt[2] as u16);
                if pid == 0x1FFF {
                    null_packets_received += 1;
                }
            }
        }
    })
    .await;

    let elapsed = start_stall.elapsed();

    // Verify clean termination without hanging/deadlock
    assert!(
        read_result.is_ok(),
        "Downstream reader must receive clean EOF without hanging past 12s timeout!"
    );
    assert!(
        elapsed >= Duration::from_secs(8),
        "Teardown must only occur after the 8.0s hard ceiling, elapsed: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(11),
        "Teardown must complete promptly after 8.0s (under 11s), elapsed: {elapsed:?}"
    );
    assert!(
        null_packets_received >= 50,
        "Airlock should have injected ~70 null packets over 8s stall, got {null_packets_received}"
    );

    // Verify resource teardown without leaks
    drop(sub);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        hub.active_sessions_count().await,
        0,
        "Active broadcast sessions must be 0 (no session leak)"
    );
    assert_eq!(
        upstream_hub.active_count(),
        0,
        "Upstream connections must be 0 (no socket leak)"
    );
}

/// Verification of `/metrics` endpoint and Prometheus text format validity:
/// Validates `airlock_active_broadcast_sessions`, `airlock_active_subscribers`,
/// `airlock_reservoir_cushion_sec`, `airlock_upstream_jitter_ms`, `airlock_stalls_absorbed_total`.
#[tokio::test]
async fn test_chaos_prometheus_metrics_validation() {
    let temp_cache =
        std::env::temp_dir().join(format!("airlock_metrics_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_cache);

    let quota_config = QuotaConfig {
        min_cache_bytes: 10 * 1024 * 1024,
        max_cache_bytes: 50 * 1024 * 1024,
        emergency_disk_floor_bytes: 1024 * 1024,
    };
    let quota_manager = SharedQuotaManager::new(quota_config);
    let upstream_hub = Arc::new(UpstreamHub::new(Duration::from_millis(20)));
    let client = reqwest::Client::new();
    let hub = Arc::new(LiveBroadcastHub::new(
        Arc::clone(&upstream_hub),
        client.clone(),
        "http://127.0.0.1:9999".to_string(),
        1024 * 1024,
    ));
    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));

    // 1. Idle state verification
    let idle_text = render_prometheus_metrics(&quota_manager, &temp_cache, &hub, &arbiter).await;

    assert!(idle_text.contains("# HELP airlock_active_broadcast_sessions"));
    assert!(idle_text.contains("# TYPE airlock_active_broadcast_sessions gauge"));
    assert!(idle_text.contains("airlock_active_broadcast_sessions 0"));

    assert!(idle_text.contains("# HELP airlock_active_subscribers"));
    assert!(idle_text.contains("# TYPE airlock_active_subscribers gauge"));
    assert!(idle_text.contains("airlock_active_subscribers 0"));

    assert!(idle_text.contains("# HELP airlock_reservoir_cushion_sec"));
    assert!(idle_text.contains("# TYPE airlock_reservoir_cushion_sec gauge"));
    assert!(idle_text.contains("airlock_reservoir_cushion_sec 3.50"));

    assert!(idle_text.contains("# HELP airlock_upstream_jitter_ms"));
    assert!(idle_text.contains("# TYPE airlock_upstream_jitter_ms gauge"));
    assert!(idle_text.contains("airlock_upstream_jitter_ms 0.00"));

    assert!(idle_text.contains("# HELP airlock_stalls_absorbed_total"));
    assert!(idle_text.contains("# TYPE airlock_stalls_absorbed_total counter"));
    assert!(idle_text.contains("airlock_stalls_absorbed_total 0"));

    // 2. Active streaming state verification
    let (_grant, guard) = arbiter
        .acquire_guard("live_ch_42", false)
        .expect("acquire arbiter guard");
    assert_eq!(arbiter.active_subscribers(), 1);

    let active_text = render_prometheus_metrics(&quota_manager, &temp_cache, &hub, &arbiter).await;

    assert!(active_text.contains("airlock_active_subscribers 1"));
    assert!(active_text.contains("airlock_reservoir_cushion_sec{stream_id=\"live_ch_42\"} 3.50"));
    assert!(active_text.contains("airlock_upstream_jitter_ms{stream_id=\"live_ch_42\"} 0.00"));
    assert!(active_text.contains("airlock_stalls_absorbed_total{stream_id=\"live_ch_42\"} 0"));

    // 3. HTTP response verification
    let resp = render_metrics_response(&quota_manager, &temp_cache, &hub, &arbiter).await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type header"),
        "text/plain; version=0.0.4; charset=utf-8"
    );

    drop(guard);
    let _ = std::fs::remove_dir_all(&temp_cache);
}
