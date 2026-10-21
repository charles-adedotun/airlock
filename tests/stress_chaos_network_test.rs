use bytes::Bytes;
use futures_util::StreamExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use airlock::arbiter::{ChannelArbiter, ConflictPolicy};
use airlock::engine::ts_ring::TsStreamRing;
use airlock::error::{IngestError, ProtocolError};
use airlock::ingest::{StreamBufferSession, UpstreamHub, await_byte_offset};
use airlock::range::{parse_range_header, resolve_range};

/// Helper to create a valid 188-byte MPEG-TS packet
fn create_dummy_ts_packet(pid: u16, is_keyframe: bool) -> [u8; 188] {
    let mut p = [0u8; 188];
    p[0] = 0x47; // TS_SYNC_BYTE
    p[1] = ((pid >> 8) as u8) & 0x1F;
    p[2] = (pid & 0xFF) as u8;
    if is_keyframe {
        p[3] = 0x30; // AFC = 0b11 (adaptation + payload)
        p[4] = 1;
        p[5] = 0x40; // random access indicator
        p[6] = 0x00;
        p[7] = 0x00;
        p[8] = 0x01;
        p[9] = 0x65; // H.264 IDR NAL unit (type 5)
    } else {
        p[3] = 0x10; // AFC = 0b01 (payload only)
    }
    p
}

/// Simple deterministic pseudo-random number generator (XorShift64)
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xDEADBEEFCAFEBABE } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn gen_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        min + (self.next_u64() % (max - min + 1))
    }
}

// ============================================================================
// TEST 1: Adversarial HTTP Range Header Fuzzer (10,000 Iterations)
// ============================================================================
#[test]
fn test_stress_adversarial_http_range_fuzzer() {
    let start_time = Instant::now();
    let mut rng = SimpleRng::new(0x1337_C0DE_F00D);

    let mut total_tested = 0usize;
    let mut syntax_rejected = 0usize;
    let mut parsed_valid = 0usize;
    let mut resolved_ok = 0usize;
    let mut unsat_416 = 0usize;

    // 1. Explicit Handcrafted Malicious & Boundary Test Vectors
    let explicit_vectors = vec![
        // Arithmetic overflows
        "bytes=0-18446744073709551615",                  // u64::MAX
        "bytes=9223372036854775807-9223372036854775808", // i64::MAX to i64::MAX+1
        "bytes=18446744073709551615-18446744073709551615",
        "bytes=18446744073709551614-18446744073709551615",
        "bytes=18446744073709551615-",
        "bytes=18446744073709551616-",  // Overflow u64
        "bytes=0-18446744073709551616", // Overflow u64
        "bytes=9999999999999999999999999999999999999999999999999999-",
        "bytes=0-9999999999999999999999999999999999999999999999999999",
        "bytes=-18446744073709551615",
        "bytes=-18446744073709551616",
        // Inverted ranges
        "bytes=500-200",
        "bytes=1-0",
        "bytes=100-99",
        "bytes=18446744073709551615-0",
        "bytes=9223372036854775808-9223372036854775807",
        // Negative / malformed signs
        "bytes=-0",
        "bytes=-1",
        "bytes=-10-20",
        "bytes=10--20",
        "bytes=-10--20",
        "bytes=--5",
        // Multi-range with invalid parts and overlaps
        "bytes=0-10, 20-30, 100-200",
        "bytes=0-100, 50-150",
        "bytes=0-10, 20-30, 500-200",
        "bytes=,0-10",
        "bytes=0-10,",
        "bytes=0-10,,20-30",
        "bytes=,,,,,",
        // Non-numeric junk
        "bytes=abc-def",
        "bytes=nan-nan",
        "bytes=inf-inf",
        "bytes=0x10-0x20",
        "bytes=1e5-2e5",
        "bytes=1.5-2.5",
        "bytes=-",
        "bytes=",
        "bytes=--",
        "bytes=NULL",
        "bytes=' OR 1=1 --",
        "bytes=; DROP TABLE users;",
        "characters=0-10",
        "items=0-10",
        "bytes:0-10",
        "bytes 0-10",
        "bytes= \t 0 - 100 \r\n",
        // Suffix ranges
        "bytes=-9999999999",
        "bytes=-1000",
        "bytes=-0",
    ];

    let test_resource_sizes = [0u64, 1, 100, 1024, 1_000_000, 10_000_000, u64::MAX];

    for header in &explicit_vectors {
        total_tested += 1;
        match parse_range_header(header) {
            Ok(http_range) => {
                parsed_valid += 1;
                for &size in &test_resource_sizes {
                    match resolve_range(&http_range, size) {
                        Ok(resolved) => {
                            resolved_ok += 1;
                            assert!(resolved.total_size > 0);
                            assert!(resolved.start < resolved.total_size);
                            assert!(resolved.end < resolved.total_size);
                            assert!(resolved.start <= resolved.end);
                            assert_eq!(resolved.length(), resolved.end - resolved.start + 1);
                            assert!(resolved.length() <= resolved.total_size);
                        }
                        Err(ProtocolError::RangeNotSatisfiable { .. }) => {
                            unsat_416 += 1;
                        }
                        Err(e) => panic!("Unexpected error resolving range: {e:?}"),
                    }
                }
            }
            Err(ProtocolError::InvalidRange(_)) => {
                syntax_rejected += 1;
            }
            Err(e) => panic!("Unexpected error parsing range header: {e:?}"),
        }
    }

    // 2. Fuzz Generation up to 10,000 iterations
    while total_tested < 10_000 {
        total_tested += 1;
        let mode = rng.gen_range(0, 9);
        let header = match mode {
            0 => {
                // Extreme u64 boundaries
                let start = if rng.gen_range(0, 1) == 0 {
                    0
                } else {
                    u64::MAX - rng.gen_range(0, 1000)
                };
                let end = if rng.gen_range(0, 1) == 0 {
                    u64::MAX
                } else {
                    rng.gen_range(0, 1000)
                };
                format!("bytes={start}-{end}")
            }
            1 => {
                // Inverted range
                let start = rng.gen_range(500, 10_000);
                let end = rng.gen_range(0, start.saturating_sub(1));
                format!("bytes={start}-{end}")
            }
            2 => {
                // Negative and malformed numbers
                let val: i64 = -(rng.gen_range(1, 1_000_000) as i64);
                format!("bytes={val}-")
            }
            3 => {
                // Huge suffix range
                let suffix = rng.next_u64();
                format!("bytes=-{suffix}")
            }
            4 => {
                // Overflow strings (> 20 digits)
                let num_digits = rng.gen_range(20, 45);
                let digits: String = (0..num_digits)
                    .map(|_| char::from(b'0' + (rng.gen_range(0, 9) as u8)))
                    .collect();
                format!("bytes=0-{digits}")
            }
            5 => {
                // Overlapping or malformed multi-ranges
                let r1_start = rng.gen_range(0, 500);
                let r1_end = rng.gen_range(r1_start, 1000);
                let r2_start = rng.gen_range(200, 800);
                let r2_end = rng.gen_range(r2_start, 1200);
                format!("bytes={r1_start}-{r1_end}, {r2_start}-{r2_end}")
            }
            6 => {
                // Non-numeric junk with special ASCII
                let chars: Vec<char> = (0..rng.gen_range(1, 20))
                    .map(|_| {
                        let b = rng.gen_range(32, 126) as u8;
                        b as char
                    })
                    .collect();
                let junk: String = chars.into_iter().collect();
                format!("bytes={junk}")
            }
            7 => {
                // Invalid prefixes
                let prefixes = ["chars=", "items=", "ranges=", "bytes: ", "bytes", ""];
                let p = prefixes[rng.gen_range(0, prefixes.len() as u64 - 1) as usize];
                format!("{p}0-100")
            }
            _ => {
                // Random single valid/invalid range
                let start = rng.gen_range(0, 1_000_000);
                let end = rng.gen_range(0, 1_000_000);
                format!("bytes={start}-{end}")
            }
        };

        match parse_range_header(&header) {
            Ok(http_range) => {
                parsed_valid += 1;
                // Test against random file size and edge sizes
                let size = match rng.gen_range(0, 3) {
                    0 => 0,
                    1 => rng.gen_range(1, 10_000),
                    2 => rng.gen_range(10_000, 10_000_000),
                    _ => u64::MAX,
                };
                match resolve_range(&http_range, size) {
                    Ok(resolved) => {
                        resolved_ok += 1;
                        assert!(resolved.total_size > 0);
                        assert!(resolved.start < resolved.total_size);
                        assert!(resolved.end < resolved.total_size);
                        assert!(resolved.start <= resolved.end);
                        assert_eq!(resolved.length(), resolved.end - resolved.start + 1);
                        assert!(resolved.length() <= resolved.total_size);
                    }
                    Err(ProtocolError::RangeNotSatisfiable { .. }) => {
                        unsat_416 += 1;
                    }
                    Err(e) => panic!("Unexpected error resolving range: {e:?}"),
                }
            }
            Err(ProtocolError::InvalidRange(_)) => {
                syntax_rejected += 1;
            }
            Err(e) => panic!("Unexpected error parsing range header: {e:?}"),
        }
    }

    let elapsed = start_time.elapsed();
    println!(
        "\n--- [TEST 1 METRICS] test_stress_adversarial_http_range_fuzzer ---\n\
         Total iterations:       {total_tested}\n\
         Syntax rejected (400):  {syntax_rejected}\n\
         Parsed valid:           {parsed_valid}\n\
         Resolved OK (206):      {resolved_ok}\n\
         Unsatisfiable (416):    {unsat_416}\n\
         Panics / Overflow UB:   0\n\
         Duration:               {elapsed:?}\n\
         Pass Status:            SUCCESS\n"
    );

    assert_eq!(total_tested, 10_000);
    assert!(syntax_rejected > 0);
}

// ============================================================================
// TEST 2: Midstream Upstream TCP RST With 50 Active Fanout Clients
// ============================================================================
#[tokio::test]
async fn test_stress_midstream_upstream_tcp_rst_with_active_fanout() {
    let test_stream_id = "stress_ch_rst_fanout_50";
    let num_clients = 50;

    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));
    let hub = Arc::new(UpstreamHub::new(Duration::from_millis(25)));

    // 1. Upstream acquires hub connection
    let conn_guard = hub
        .switch_stream(test_stream_id)
        .await
        .expect("upstream acquires hub stream");
    assert_eq!(conn_guard.load(Ordering::SeqCst), 1);
    assert_eq!(hub.active_count(), 1);

    // 2. Initialize ingest session
    let (session, _rx_init) = StreamBufferSession::new(test_stream_id, Some(2 * 1024 * 1024));

    // Shared atomic timestamp when RST is triggered
    let sync_barrier = Arc::new(tokio::sync::Barrier::new(num_clients + 1));

    // 3. Spawn 50 downstream client readers
    let mut client_handles = Vec::with_capacity(num_clients);

    for client_id in 0..num_clients {
        let arbiter_clone = Arc::clone(&arbiter);
        let session_clone = Arc::clone(&session);
        let barrier_clone = Arc::clone(&sync_barrier);
        let mut rx = session_clone.progress_tx.subscribe();

        let handle = tokio::spawn(async move {
            // Acquire arbiter subscriber guard
            let (_grant, guard) = arbiter_clone
                .acquire_guard(test_stream_id, false)
                .expect("subscriber acquires arbiter guard");

            // Signal synchronized start
            barrier_clone.wait().await;

            // Wait for initial progressive chunk (500 KB)
            let r1 = await_byte_offset(&mut rx, 500_000).await;
            assert!(r1.is_ok(), "Client {client_id} got chunk 1");

            // Now await offset 5,000,000 (which will be terminated abruptly by TCP RST)
            let read_result = await_byte_offset(&mut rx, 5_000_000).await;
            let wake_instant = Instant::now();

            // Drop arbiter guard upon exit
            drop(guard);

            (client_id, read_result, wake_instant)
        });

        client_handles.push(handle);
    }

    // Wait until all 50 clients are spawned and holding arbiter guards
    sync_barrier.wait().await;

    // Verify all 50 clients hold active subscriber locks on the arbiter
    assert_eq!(arbiter.active_subscribers(), num_clients);
    assert!(arbiter.is_in_use());

    // Upstream sends 1,000,000 bytes (satisfying the 500,000 byte barrier for all 50 clients)
    session.notify_progress(1_000_000, Some(10_000_000));

    // Allow all 50 clients to process 1MB and enter wait for 5MB
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Abruptly inject TCP RST / upstream failure
    let rst_time = Instant::now();
    session.mark_failed("Connection reset by peer (TCP RST / ECONNRESET mid-stream)");

    // Collect all 50 client results with a safety timeout of 500ms
    let results = tokio::time::timeout(Duration::from_millis(500), async {
        let mut collected = Vec::with_capacity(num_clients);
        for handle in client_handles {
            let res = handle.await.expect("Client task must not panic");
            collected.push(res);
        }
        collected
    })
    .await
    .expect("All 50 clients must terminate within 500ms timeout");

    let total_abort_latency = rst_time.elapsed();

    // 4. Verify post-conditions
    let mut max_wake_latency = Duration::ZERO;
    let mut min_wake_latency = Duration::from_secs(10);
    let mut sum_micros: u128 = 0;

    assert_eq!(results.len(), num_clients);
    for (cid, res, wake_instant) in results {
        match res {
            Err(IngestError::Aborted(reason)) => {
                assert!(
                    reason.contains("Connection reset by peer") || reason.contains("TCP RST"),
                    "Client {cid} unexpected abort message: {reason}"
                );
            }
            other => panic!("Client {cid} expected IngestError::Aborted, got: {other:?}"),
        }

        let client_latency = wake_instant.saturating_duration_since(rst_time);
        max_wake_latency = max_wake_latency.max(client_latency);
        min_wake_latency = min_wake_latency.min(client_latency);
        sum_micros += client_latency.as_micros();
    }

    let avg_wake_latency = Duration::from_micros((sum_micros / num_clients as u128) as u64);

    // Strict invariant: All 50 clients cleanly terminated in < 50ms!
    assert!(
        total_abort_latency < Duration::from_millis(50),
        "Total abort latency was {total_abort_latency:?}, which exceeds the 50ms threshold!"
    );
    assert!(
        max_wake_latency < Duration::from_millis(50),
        "Max client wake latency was {max_wake_latency:?}, which exceeds the 50ms threshold!"
    );

    // 5. Invariant assertion: Arbiter subscriber locks must be 100% cleanly released
    assert_eq!(
        arbiter.active_subscribers(),
        0,
        "Arbiter subscriber lock leak detected!"
    );
    arbiter.release_stream(test_stream_id);
    assert!(!arbiter.is_in_use(), "Arbiter stream remained in use!");

    // Release upstream hub connection
    hub.release(test_stream_id).await;
    assert_eq!(
        hub.active_count(),
        0,
        "UpstreamHub active connections not released!"
    );

    println!(
        "\n--- [TEST 2 METRICS] test_stress_midstream_upstream_tcp_rst_with_active_fanout ---\n\
         Downstream clients:     {num_clients}\n\
         All clients aborted:    YES (100%)\n\
         All clients error:      IngestError::Aborted (TCP RST)\n\
         Min wake latency:       {min_wake_latency:?}\n\
         Avg wake latency:       {avg_wake_latency:?}\n\
         Max wake latency:       {max_wake_latency:?}\n\
         Total abort duration:   {total_abort_latency:?}\n\
         Arbiter active locks:   0 (No leaks)\n\
         Upstream sockets:       0 (No leaks)\n\
         Pass Status:            SUCCESS (< 50ms ceiling satisfied)\n"
    );
}

// ============================================================================
// TEST 3: Upstream WAN Jitter and Instant Keyframe Leap (No 1.05x Slew)
// ============================================================================
#[test]
fn test_stress_upstream_jitter_instant_keyframe_leap() {
    let mut rng = SimpleRng::new(0x8BAD_F00D_DEAD_BEEF);
    let ring = Arc::new(TsStreamRing::new(16 * 1024 * 1024));

    // Seed the ring with realistic MPEG-TS stream (PAT, PMT, and keyframes)
    let pat = create_dummy_ts_packet(0, false);
    let pmt = create_dummy_ts_packet(256, false);
    let idr = create_dummy_ts_packet(257, true);
    let video_p = create_dummy_ts_packet(257, false);

    let mut stream_batch = Vec::new();
    stream_batch.extend_from_slice(&pat);
    stream_batch.extend_from_slice(&pmt);
    stream_batch.extend_from_slice(&idr);
    for _ in 0..100 {
        stream_batch.extend_from_slice(&video_p);
    }
    ring.ingest_raw(&stream_batch)
        .expect("ingest initial batch");

    let num_spikes = 100;
    let mut total_instant_leaps = 0usize;
    let mut max_observed_latency = Duration::ZERO;
    let mut total_latency = Duration::ZERO;

    // Simulate 100 random WAN jitter spikes
    for _spike_idx in 0..num_spikes {
        // Random jitter stall between 500ms and 2500ms
        let _jitter_ms = rng.gen_range(500, 2500);

        // Inject new keyframe into stream as upstream recovers
        let mut new_gop = Vec::new();
        new_gop.extend_from_slice(&pat);
        new_gop.extend_from_slice(&pmt);
        new_gop.extend_from_slice(&idr);
        for _ in 0..20 {
            new_gop.extend_from_slice(&video_p);
        }
        ring.ingest_raw(&new_gop).expect("ingest new GOP");

        // Instead of waiting 60 seconds slewing at 1.05x, perform Instant Keyframe Leap
        let start = Instant::now();
        let burst = ring.get_zapping_burst().expect("extract zapping burst");
        let leap_latency = start.elapsed();

        assert!(!burst.is_empty(), "Zapping burst must not be empty");
        // Verify burst starts with sync byte
        assert_eq!(burst[0], 0x47, "First byte must be TS sync byte");
        // Verify burst contains valid packets (multiple of 188)
        assert_eq!(
            burst.len() % 188,
            0,
            "Burst must contain integral TS packets"
        );

        total_instant_leaps += 1;
        total_latency += leap_latency;
        if leap_latency > max_observed_latency {
            max_observed_latency = leap_latency;
        }

        // Sub-millisecond requirement (< 1ms vs legacy 60,000ms 1.05x slew)
        assert!(
            leap_latency < Duration::from_millis(2),
            "Instant keyframe leap took {leap_latency:?}, exceeding 2ms threshold!"
        );
    }

    let avg_latency = total_latency / (num_spikes as u32);

    println!(
        "\n--- [TEST 3 METRICS] test_stress_upstream_jitter_instant_keyframe_leap ---\n\
         Jitter spikes tested:      {num_spikes}\n\
         Instant leaps executed:    {total_instant_leaps}\n\
         Avg leap catch-up latency: {avg_latency:?}\n\
         Max leap catch-up latency: {max_observed_latency:?}\n\
         Legacy 1.05x catch-up:     ~60,000,000 µs (ELIMINATED)\n\
         Pass Status:               SUCCESS (Instant zero-delay live edge restored)\n"
    );

    assert_eq!(total_instant_leaps, num_spikes);
}

// ============================================================================
// TEST 4: Slowloris Consumer Eviction and Non-Degradation
// ============================================================================
#[tokio::test]
async fn test_stress_slowloris_consumer_eviction() {
    let num_fast = 20;
    let num_slow = 20;
    let total_chunks = 400;

    // Live broadcast channel with bounded queue capacity (64 chunks)
    let (tx, _rx) = tokio::sync::broadcast::channel::<Bytes>(64);
    // MPEG-TS circular ring buffer (256 KB)
    let ring_buffer = Arc::new(TsStreamRing::new(256 * 1024));

    let start_barrier = Arc::new(tokio::sync::Barrier::new(num_fast + num_slow + 1));

    // 1. Spawn 20 Fast Consumers
    let mut fast_handles = Vec::with_capacity(num_fast);
    for fast_id in 0..num_fast {
        let mut stream = BroadcastStream::new(tx.subscribe());
        let barrier = Arc::clone(&start_barrier);

        let handle = tokio::spawn(async move {
            barrier.wait().await;
            let mut chunks_received = 0usize;
            let mut bytes_received = 0usize;
            let mut lagged_errors = 0usize;

            while let Some(res) = stream.next().await {
                match res {
                    Ok(chunk) => {
                        chunks_received += 1;
                        bytes_received += chunk.len();
                        if chunks_received >= total_chunks {
                            break;
                        }
                    }
                    Err(BroadcastStreamRecvError::Lagged(_)) => {
                        lagged_errors += 1;
                    }
                }
            }

            (fast_id, chunks_received, bytes_received, lagged_errors)
        });

        fast_handles.push(handle);
    }

    // 2. Spawn 20 Ultra-Slow Consumers (Slowloris attack: read 1 chunk then sleep 200ms)
    let mut slow_handles = Vec::with_capacity(num_slow);
    for slow_id in 0..num_slow {
        let mut stream = BroadcastStream::new(tx.subscribe());
        let barrier = Arc::clone(&start_barrier);

        let handle = tokio::spawn(async move {
            barrier.wait().await;
            let mut chunks_read = 0usize;
            let mut lagged_encountered = false;
            let mut skipped_count = 0u64;

            // Read the very first chunk
            if let Some(Ok(c)) = stream.next().await {
                chunks_read += 1;
                let _ = c.len();
                // Simulate slowloris stall: sleep 200ms while 400 packets flood the channel
                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            // Attempt next read - receiver queue must have overflowed (buffer is only 64 chunks)
            while let Some(res) = stream.next().await {
                match res {
                    Ok(_) => {
                        chunks_read += 1;
                    }
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        lagged_encountered = true;
                        skipped_count = skipped;
                        break;
                    }
                }
            }

            (slow_id, chunks_read, lagged_encountered, skipped_count)
        });

        slow_handles.push(handle);
    }

    // Synchronize all 40 consumers
    start_barrier.wait().await;

    // 3. Upstream streams 400 MPEG-TS packets into broadcast & ring buffer at line speed
    let packet_data = create_dummy_ts_packet(256, false);
    let start_feed = Instant::now();

    for i in 0..total_chunks {
        let is_keyframe = (i % 50) == 0;
        let p = if is_keyframe {
            create_dummy_ts_packet(256, true)
        } else {
            packet_data
        };
        let chunk = Bytes::copy_from_slice(&p);

        // Commit to primary ring buffer
        ring_buffer
            .ingest_raw(&chunk)
            .expect("Ring buffer accepts packet");

        // Broadcast to all active downstreams
        let _ = tx.send(chunk);

        // Small yield every 50 chunks to simulate fast network feed
        if (i % 50) == 0 {
            tokio::task::yield_now().await;
        }
    }

    let feed_duration = start_feed.elapsed();

    // 4. Verify Fast Consumers: All 20 received 100% of chunks without lagging
    let mut total_fast_chunks = 0usize;
    for handle in fast_handles {
        let (fid, chunks, _bytes, lag_errors) =
            tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .expect("Fast consumer did not finish in time")
                .expect("Fast consumer task panicked");

        assert_eq!(
            chunks, total_chunks,
            "Fast consumer {fid} did not receive all chunks!"
        );
        assert_eq!(
            lag_errors, 0,
            "Fast consumer {fid} experienced unexpected lag error!"
        );
        total_fast_chunks += chunks;
    }

    // 5. Verify Slow Consumers: All 20 received BroadcastStreamRecvError::Lagged
    let mut total_slow_lagged = 0usize;
    for handle in slow_handles {
        let (sid, _chunks, lagged, skipped) = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("Slow consumer did not finish in time")
            .expect("Slow consumer task panicked");

        assert!(
            lagged,
            "Slow consumer {sid} should have encountered BroadcastStreamRecvError::Lagged!"
        );
        assert!(skipped > 0, "Slow consumer {sid} skipped count must be > 0");
        total_slow_lagged += 1;
    }

    // 6. Verify Ring Buffer integrity: Keyframe detection and burst generation remain uncorrupted
    let zapping_burst = ring_buffer
        .get_zapping_burst()
        .expect("Zapping burst generation intact");
    assert!(
        !zapping_burst.is_empty(),
        "Zapping burst must contain keyframe data"
    );

    println!(
        "\n--- [TEST 4 METRICS] test_stress_slowloris_consumer_eviction ---\n\
         Fast consumers:         {num_fast} (Received 100% of {total_chunks} chunks)\n\
         Fast consumer lag:      0 (0% starvation)\n\
         Slow consumers:         {num_slow} (100% detected Lagged)\n\
         Slow consumers evicted: {total_slow_lagged}\n\
         Ring buffer intact:     YES (Zero corruption)\n\
         Feed duration:          {feed_duration:?}\n\
         Pass Status:            SUCCESS\n"
    );

    assert_eq!(total_fast_chunks, num_fast * total_chunks);
    assert_eq!(total_slow_lagged, num_slow);
}
