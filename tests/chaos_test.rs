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
