//! High-Intensity Stress & Concurrency Test Suite for Airlock Ring Buffers
//!
//! Tests:
//! 1. `test_stress_massive_fanout_500_readers`:
//!    Single writer pushing 50,000 MPEG-TS packets with 500 concurrent reader tokio tasks.
//!    Verifies zero data corruption, zero panics, contiguous sequence tracking, and zero deadlocks.
//! 2. `test_stress_ring_wrap_around_saturation`:
//!    Pushes 200 MB of streaming chunks through a 16 MB ring buffer (wrapping around ~12.5x).
//!    Verifies deterministic FIFO ring buffer eviction, memory bounding, and clean underflow handling.
//! 3. `test_stress_malformed_ts_resync_under_load`:
//!    Injects random bit flips, truncated packets, missing sync bytes, and fragmented streams
//!    at > 50,000 pkts/sec into `TsRingSynchronizer`. Verifies 100% recovery of PAT/PMT/IDR frames.
//! 4. `test_stress_zapping_burst_latency_under_load`:
//!    Measures latency to extract sub-second zapping bursts (PAT + PMT + SPS/PPS + IDR)
//!    while writer is streaming at full throughput. Verifies latency < 2ms.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::task::JoinSet;

use airlock::engine::{
    TS_PACKET_SIZE, TS_SYNC_BYTE, TsRingSynchronizer, TsStreamRing, extract_pmt_pid_from_pat,
    extract_video_pid_from_pmt, parse_ts_packet,
};
use airlock::error::StorageError;
use airlock::ring::LiveRingBuffer;

/// Serializes execution across tests in this binary so that heavy fanout tests (500 tasks)
/// do not cause CPU thread preemption during sub-millisecond latency benchmarking tests.
static SUITE_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ============================================================================
// Packet Generation Helpers
// ============================================================================

fn build_ts_packet(
    pid: u16,
    pusi: bool,
    adaptation: Option<(bool, Vec<u8>)>,
    payload: &[u8],
) -> [u8; TS_PACKET_SIZE] {
    let mut pkt = [0xFFu8; TS_PACKET_SIZE];
    pkt[0] = TS_SYNC_BYTE;
    pkt[1] = (((pid >> 8) as u8) & 0x1F) | if pusi { 0x40 } else { 0x00 };
    pkt[2] = (pid & 0xFF) as u8;

    let mut offset = 4;
    match adaptation {
        Some((random_access, extra)) => {
            pkt[3] = 0x30; // adaptation + payload
            let af_len = 1 + extra.len();
            pkt[4] = af_len as u8;
            pkt[5] = if random_access { 0x40 } else { 0x00 };
            if !extra.is_empty() {
                pkt[6..6 + extra.len()].copy_from_slice(&extra);
            }
            offset = 5 + af_len;
        }
        None => {
            pkt[3] = 0x10; // payload only
        }
    }

    if offset < TS_PACKET_SIZE && !payload.is_empty() {
        let copy_len = payload.len().min(TS_PACKET_SIZE - offset);
        pkt[offset..offset + copy_len].copy_from_slice(&payload[..copy_len]);
    }

    pkt
}

/// Creates a sequenced 188-byte MPEG-TS packet with sequence number and inverted checksum embedded.
fn create_sequenced_packet(seq: u64, is_keyframe: bool) -> Bytes {
    let mut pkt = [0u8; TS_PACKET_SIZE];
    pkt[0] = TS_SYNC_BYTE;
    pkt[1] = 0x01; // PID 256 high byte
    pkt[2] = 0x00; // PID 256 low byte

    if is_keyframe {
        // AFC = 0b11 (adaptation + payload), random access indicator = true
        pkt[3] = 0x30;
        pkt[4] = 1; // adaptation length = 1
        pkt[5] = 0x40; // random access flag
        // H.264 IDR NAL start code (00 00 01 65)
        pkt[6] = 0x00;
        pkt[7] = 0x00;
        pkt[8] = 0x01;
        pkt[9] = 0x65;
        // Embed sequence in bytes 10..18 and inverted checksum in 18..26
        pkt[10..18].copy_from_slice(&seq.to_be_bytes());
        pkt[18..26].copy_from_slice(&(!seq).to_be_bytes());
        // Fill remaining with sequence pattern
        for (i, b) in pkt[26..].iter_mut().enumerate() {
            *b = ((seq.wrapping_add(i as u64)) & 0xFF) as u8;
        }
    } else {
        // AFC = 0b01 (payload only)
        pkt[3] = 0x10;
        // Embed sequence in bytes 4..12 and inverted checksum in 12..20
        pkt[4..12].copy_from_slice(&seq.to_be_bytes());
        pkt[12..20].copy_from_slice(&(!seq).to_be_bytes());
        // Fill remaining with sequence pattern
        for (i, b) in pkt[20..].iter_mut().enumerate() {
            *b = ((seq.wrapping_add(i as u64)) & 0xFF) as u8;
        }
    }

    Bytes::copy_from_slice(&pkt)
}

/// Generates non-sync pseudo-random noise bytes (guaranteed never to contain TS_SYNC_BYTE).
fn make_non_sync_noise(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|j| {
            let b = ((seed * 31 + j * 17 + 1) % 255) as u8;
            if b == TS_SYNC_BYTE { 0x48 } else { b }
        })
        .collect()
}

/// Generates a valid synthetic Program Association Table (PAT) packet.
fn build_pat_packet(pmt_pid: u16) -> [u8; TS_PACKET_SIZE] {
    let pat_payload = vec![
        0x00, // pointer field
        0x00, // table ID = 0 (PAT)
        0xB0,
        0x0D, // section syntax + length (13 bytes)
        0x00,
        0x01, // transport stream ID
        0xC1, // current_next
        0x00, // section 0
        0x00, // last section 0
        0x00,
        0x01, // program number = 1
        ((pmt_pid >> 8) as u8 & 0x1F) | 0xE0,
        (pmt_pid & 0xFF) as u8,
        0x00,
        0x00,
        0x00,
        0x00, // CRC placeholder
    ];
    build_ts_packet(0, true, None, &pat_payload)
}

/// Generates a valid synthetic Program Map Table (PMT) packet.
fn build_pmt_packet(pmt_pid: u16, video_pid: u16) -> [u8; TS_PACKET_SIZE] {
    let pmt_payload = vec![
        0x00, // pointer field
        0x02, // table ID = 2 (PMT)
        0xB0,
        0x12, // section syntax + length (18 bytes)
        0x00,
        0x01, // program number 1
        0xC1, // current_next
        0x00,
        0x00, // section/last
        ((video_pid >> 8) as u8 & 0x1F) | 0xE0,
        (video_pid & 0xFF) as u8, // PCR PID
        0xF0,
        0x00, // program info length = 0
        0x1B, // stream type = H.264
        ((video_pid >> 8) as u8 & 0x1F) | 0xE0,
        (video_pid & 0xFF) as u8,
        0xF0,
        0x00, // ES info length = 0
        0x00,
        0x00,
        0x00,
        0x00, // CRC placeholder
    ];
    build_ts_packet(pmt_pid, true, None, &pmt_payload)
}

/// Generates a valid H.264 SPS/PPS packet.
fn build_sps_pps_packet(video_pid: u16) -> [u8; TS_PACKET_SIZE] {
    let sps_payload = [
        0x00, 0x00, 0x01, 0x07, 0x64, 0x00, 0x1F, // SPS
        0x00, 0x00, 0x01, 0x08, 0x68, 0xEB, 0xE3, // PPS
    ];
    build_ts_packet(video_pid, true, None, &sps_payload)
}

/// Generates a valid H.264 IDR keyframe packet.
fn build_idr_packet(video_pid: u16, seq: u64) -> [u8; TS_PACKET_SIZE] {
    let mut payload = vec![0x00, 0x00, 0x01, 0x05, 0x88, 0x99];
    payload.extend_from_slice(&seq.to_be_bytes());
    build_ts_packet(video_pid, true, Some((true, vec![])), &payload)
}

// ============================================================================
// Test 1: Massive Fanout 500 Readers Stress Test
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_massive_fanout_500_readers() {
    let _suite_lock = SUITE_MUTEX.lock().await;

    const TOTAL_PACKETS: u64 = 50_000;
    const NUM_READERS: usize = 500;
    const RING_CAPACITY_BYTES: usize = 16 * 1024 * 1024; // 16 MB: fits all 50k packets (9.4 MB)

    println!("\n=== Starting test_stress_massive_fanout_500_readers ===");
    println!(
        "Writer workload: {TOTAL_PACKETS} packets ({} MB)",
        (TOTAL_PACKETS * TS_PACKET_SIZE as u64) as f64 / 1_048_576.0
    );
    println!("Concurrent reader tasks: {NUM_READERS}");

    let ring = Arc::new(LiveRingBuffer::new(RING_CAPACITY_BYTES));
    let writer_done = Arc::new(AtomicBool::new(false));
    let total_packets_read = Arc::new(AtomicU64::new(0));

    let start_instant = Instant::now();

    // 1. Spawn 500 concurrent reader tasks across varied starting sequences and batch sizes
    let mut reader_set = JoinSet::new();

    for reader_id in 0..NUM_READERS {
        let ring_clone = ring.clone();
        let writer_done_clone = writer_done.clone();
        let total_packets_read_clone = total_packets_read.clone();

        // Stagger reader configurations to stress lock contention and sequence offsets
        let (start_seq, batch_size) = match reader_id % 4 {
            0 => (0u64, 64),
            1 => (0u64, 128),
            2 => (((reader_id * 37) % 5000) as u64, 32),
            _ => (((reader_id * 71) % 10000) as u64, 16),
        };

        reader_set.spawn(async move {
            let mut curr_seq = start_seq;
            let mut reader_read_count = 0u64;

            loop {
                let (chunks, next_seq) = match ring_clone.read_from(curr_seq, batch_size) {
                    Ok(res) => res,
                    Err(err) => panic!("Reader {reader_id} encountered unexpected read error: {err:?}"),
                };

                if chunks.is_empty() {
                    if writer_done_clone.load(Ordering::Acquire) {
                        // Double check if write head is truly exhausted
                        if let Ok((retry_chunks, _)) = ring_clone.read_from(curr_seq, batch_size) {
                            if retry_chunks.is_empty() {
                                break;
                            }
                        }
                    }
                    tokio::task::yield_now().await;
                    continue;
                }

                for chunk in &chunks {
                    // Invariant 1: Contiguous sequence tracking without gaps
                    assert_eq!(
                        chunk.sequence, curr_seq,
                        "Reader {reader_id}: sequence gap detected! expected {curr_seq}, got {}",
                        chunk.sequence
                    );

                    // Invariant 2: Packet size correctness
                    assert_eq!(
                        chunk.data.len(),
                        TS_PACKET_SIZE,
                        "Reader {reader_id}: invalid packet size {}",
                        chunk.data.len()
                    );

                    // Invariant 3: Zero data corruption - TS sync byte integrity
                    assert_eq!(
                        chunk.data[0], TS_SYNC_BYTE,
                        "Reader {reader_id}: corrupted sync byte at seq {curr_seq}"
                    );

                    // Invariant 4: Zero data corruption - Sequence and checksum validation
                    let (embedded_seq, checksum) = if chunk.is_keyframe {
                        let s = u64::from_be_bytes(chunk.data[10..18].try_into().expect("slice"));
                        let c = u64::from_be_bytes(chunk.data[18..26].try_into().expect("slice"));
                        (s, c)
                    } else {
                        let s = u64::from_be_bytes(chunk.data[4..12].try_into().expect("slice"));
                        let c = u64::from_be_bytes(chunk.data[12..20].try_into().expect("slice"));
                        (s, c)
                    };

                    assert_eq!(
                        embedded_seq, curr_seq,
                        "Reader {reader_id}: corrupted sequence in payload! expected {curr_seq}, got {embedded_seq}"
                    );
                    assert_eq!(
                        checksum, !curr_seq,
                        "Reader {reader_id}: checksum corruption at seq {curr_seq}"
                    );

                    curr_seq += 1;
                    reader_read_count += 1;
                }

                assert_eq!(next_seq, curr_seq);

                if curr_seq >= TOTAL_PACKETS && writer_done_clone.load(Ordering::Acquire) {
                    break;
                }
            }

            total_packets_read_clone.fetch_add(reader_read_count, Ordering::Relaxed);
            reader_read_count
        });
    }

    // 2. Writer task: Pushes 50,000 sequenced MPEG-TS packets into the ring buffer
    let ring_writer = ring.clone();
    let write_start = Instant::now();

    for seq in 0..TOTAL_PACKETS {
        let is_keyframe = seq % 100 == 0;
        let pkt = create_sequenced_packet(seq, is_keyframe);
        let pushed_seq = ring_writer
            .push(pkt, is_keyframe)
            .expect("ring buffer push must succeed");
        assert_eq!(pushed_seq, seq);

        if seq % 512 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let write_duration = write_start.elapsed();
    writer_done.store(true, Ordering::Release);

    // 3. Await all 500 readers to ensure clean termination without deadlocks
    let mut reader_completed = 0;
    while let Some(res) = reader_set.join_next().await {
        match res {
            Ok(count) => {
                assert!(count > 0, "Reader processed zero packets!");
                reader_completed += 1;
            }
            Err(e) => panic!("Reader task failed or panicked: {e:?}"),
        }
    }

    let total_duration = start_instant.elapsed();
    let total_read = total_packets_read.load(Ordering::Relaxed);
    let total_read_bytes = total_read * TS_PACKET_SIZE as u64;
    let write_bytes = TOTAL_PACKETS * TS_PACKET_SIZE as u64;

    let write_throughput_mb = (write_bytes as f64 / 1_048_576.0) / write_duration.as_secs_f64();
    let aggregate_read_throughput_mb =
        (total_read_bytes as f64 / 1_048_576.0) / total_duration.as_secs_f64();

    println!("--- Fanout 500 Metrics ---");
    println!("Total packets written: {TOTAL_PACKETS}");
    println!("Write duration: {write_duration:.4?}");
    println!(
        "Write throughput: {write_throughput_mb:.2} MB/s ({} pkts/sec)",
        (TOTAL_PACKETS as f64 / write_duration.as_secs_f64()) as u64
    );
    println!("Completed readers: {reader_completed}/{NUM_READERS}");
    println!(
        "Total packets verified & read: {total_read} ({} MB aggregate)",
        total_read_bytes / 1_048_576
    );
    println!("Aggregate read throughput: {aggregate_read_throughput_mb:.2} MB/s");
    println!("Total test duration: {total_duration:.4?}");
    println!("Status: PASSED (Zero data corruption, zero panics, zero deadlocks)");

    assert_eq!(reader_completed, NUM_READERS);
    assert!(total_read >= TOTAL_PACKETS * 250); // At least half the readers read all 50k packets
}

// ============================================================================
// Test 2: Ring Wrap-Around Saturation & Deterministic FIFO Eviction
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_ring_wrap_around_saturation() {
    let _suite_lock = SUITE_MUTEX.lock().await;

    const CAPACITY_BYTES: usize = 16 * 1024 * 1024; // 16 MB ring
    const TOTAL_DATA_BYTES: usize = 200 * 1024 * 1024; // 200 MB streaming chunks
    const CHUNK_SIZE: usize = 16 * 1024; // 16 KB chunks
    const TOTAL_CHUNKS: usize = TOTAL_DATA_BYTES / CHUNK_SIZE; // 12,800 chunks
    const CAPACITY_CHUNKS: usize = CAPACITY_BYTES / CHUNK_SIZE; // 1,024 chunks

    println!("\n=== Starting test_stress_ring_wrap_around_saturation ===");
    println!(
        "Buffer Capacity: {} MB ({CAPACITY_CHUNKS} chunks)",
        CAPACITY_BYTES / 1_048_576
    );
    println!(
        "Streaming Inflow: {} MB ({TOTAL_CHUNKS} chunks)",
        TOTAL_DATA_BYTES / 1_048_576
    );
    println!(
        "Wrap-around factor: {:.2}x",
        TOTAL_CHUNKS as f64 / CAPACITY_CHUNKS as f64
    );

    let ring = Arc::new(LiveRingBuffer::new(CAPACITY_BYTES));
    let writer_done = Arc::new(AtomicBool::new(false));
    let underflows_recovered = Arc::new(AtomicUsize::new(0));

    // Spawn concurrent readers to verify sequence updates and underflow recovery under saturation
    let mut reader_set = JoinSet::new();

    // Reader 1: Fast tracking reader
    {
        let ring_clone = ring.clone();
        let writer_done_clone = writer_done.clone();
        reader_set.spawn(async move {
            let mut curr_seq = 0u64;
            let mut read_chunks = 0usize;
            while !writer_done_clone.load(Ordering::Acquire) || read_chunks < 100 {
                match ring_clone.read_from(curr_seq, 64) {
                    Ok((chunks, next_seq)) => {
                        if !chunks.is_empty() {
                            read_chunks += chunks.len();
                            curr_seq = next_seq;
                        } else {
                            tokio::task::yield_now().await;
                        }
                    }
                    Err(StorageError::RingUnderflow { oldest, .. }) => {
                        curr_seq = oldest;
                    }
                    Err(e) => panic!("Fast reader error: {e:?}"),
                }
            }
            read_chunks
        });
    }

    // Reader 2: Lagging reader that regularly experiences RingUnderflow and resyncs
    {
        let ring_clone = ring.clone();
        let writer_done_clone = writer_done.clone();
        let underflows_clone = underflows_recovered.clone();
        reader_set.spawn(async move {
            let mut curr_seq = 0u64;
            let mut handled_underflows = 0usize;
            while !writer_done_clone.load(Ordering::Acquire) {
                // Sleep momentarily to intentionally fall behind eviction horizon
                tokio::time::sleep(Duration::from_millis(5)).await;

                match ring_clone.read_from(curr_seq, 32) {
                    Ok((chunks, next_seq)) => {
                        if !chunks.is_empty() {
                            curr_seq = next_seq;
                        }
                    }
                    Err(StorageError::RingUnderflow { requested, oldest }) => {
                        assert!(
                            requested < oldest,
                            "Underflow invariant violated: requested {requested} >= oldest {oldest}"
                        );
                        // Cleanly handle sequence update by leaping to oldest retained chunk
                        curr_seq = oldest;
                        handled_underflows += 1;
                        underflows_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => panic!("Lagging reader error: {e:?}"),
                }
            }
            handled_underflows
        });
    }

    // Writer: Pushes 200 MB through the 16 MB ring buffer
    let write_start = Instant::now();
    for seq in 0..TOTAL_CHUNKS {
        let is_keyframe = seq % 64 == 0;
        let mut chunk_bytes = vec![0u8; CHUNK_SIZE];
        // Embed chunk sequence in header
        chunk_bytes[0..8].copy_from_slice(&(seq as u64).to_be_bytes());
        chunk_bytes[8..16].copy_from_slice(&(!(seq as u64)).to_be_bytes());

        let pushed_seq = ring
            .push(Bytes::from(chunk_bytes), is_keyframe)
            .expect("push must succeed");
        assert_eq!(pushed_seq, seq as u64);

        // Verify deterministic FIFO bounds at critical checkpoints
        if seq % 2000 == 0 && seq > CAPACITY_CHUNKS {
            let stats = ring.stats().expect("stats");
            // Memory bound invariant: total_bytes must never exceed max_capacity_bytes (+ at most 1 chunk during push)
            assert!(
                stats.total_bytes <= CAPACITY_BYTES + CHUNK_SIZE,
                "Memory leak detected! total_bytes: {} exceeds capacity {}",
                stats.total_bytes,
                CAPACITY_BYTES
            );
            assert!(
                stats.chunk_count <= CAPACITY_CHUNKS + 1,
                "Chunk count overflow: {}",
                stats.chunk_count
            );
        }

        if seq % 256 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let write_duration = write_start.elapsed();
    writer_done.store(true, Ordering::Release);

    // Wait for readers to finish
    while let Some(res) = reader_set.join_next().await {
        res.expect("Reader task finished");
    }

    // 4. Verify Final State & Deterministic FIFO Invariants
    let final_stats = ring.stats().expect("final stats");

    let expected_oldest_seq = (TOTAL_CHUNKS - CAPACITY_CHUNKS) as u64;
    let expected_newest_seq = (TOTAL_CHUNKS - 1) as u64;

    println!("--- Ring Wrap-Around Saturation Metrics ---");
    println!(
        "Total data pushed: {:.2} MB",
        TOTAL_DATA_BYTES as f64 / 1_048_576.0
    );
    println!("Write duration: {write_duration:.4?}");
    println!(
        "Write throughput: {:.2} MB/s",
        (TOTAL_DATA_BYTES as f64 / 1_048_576.0) / write_duration.as_secs_f64()
    );
    println!("Buffer capacity: {} MB", CAPACITY_BYTES / 1_048_576);
    println!(
        "Final buffer bytes: {:.2} MB",
        final_stats.total_bytes as f64 / 1_048_576.0
    );
    println!(
        "Total bytes written (telemetry): {:.2} MB",
        final_stats.total_bytes_written as f64 / 1_048_576.0
    );
    println!("Final chunk count: {}", final_stats.chunk_count);
    println!(
        "Expected oldest seq: {expected_oldest_seq}, Actual: {:?}",
        final_stats.oldest_sequence
    );
    println!(
        "Expected newest seq: {expected_newest_seq}, Actual: {:?}",
        final_stats.newest_sequence
    );
    println!("Total chunks evicted: {expected_oldest_seq}");
    println!(
        "Underflows cleanly handled: {}",
        underflows_recovered.load(Ordering::Relaxed)
    );

    // Verify deterministic FIFO bounds
    assert_eq!(final_stats.total_bytes_written, TOTAL_DATA_BYTES as u64);
    assert!(final_stats.total_bytes <= CAPACITY_BYTES);
    assert_eq!(final_stats.oldest_sequence, Some(expected_oldest_seq));
    assert_eq!(final_stats.newest_sequence, Some(expected_newest_seq));
    assert_eq!(final_stats.chunk_count, CAPACITY_CHUNKS);

    // Verify reading evicted sequence 0 deterministically returns RingUnderflow
    let underflow_err = ring.read_from(0, 1).unwrap_err();
    match underflow_err {
        StorageError::RingUnderflow { requested, oldest } => {
            assert_eq!(requested, 0);
            assert_eq!(oldest, expected_oldest_seq);
        }
        other => panic!("Expected RingUnderflow, got: {other:?}"),
    }

    // Verify reading valid retained sequence succeeds with exact data
    let (retained_chunks, next) = ring
        .read_from(expected_oldest_seq, 1)
        .expect("retained read");
    assert_eq!(retained_chunks.len(), 1);
    assert_eq!(retained_chunks[0].sequence, expected_oldest_seq);
    let chunk_seq = u64::from_be_bytes(retained_chunks[0].data[0..8].try_into().expect("bytes"));
    assert_eq!(chunk_seq, expected_oldest_seq);
    assert_eq!(next, expected_oldest_seq + 1);

    println!("Status: PASSED (Deterministic FIFO eviction verified, zero memory leaks)");
}

// ============================================================================
// Test 3: Malformed TS Resynchronization Under Load (TsRingSynchronizer)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_malformed_ts_resync_under_load() {
    let _suite_lock = SUITE_MUTEX.lock().await;

    const TOTAL_VALID_PACKETS: usize = 50_000;
    const PAT_INTERVAL: usize = 50; // Injects 1,000 PAT packets
    const PMT_INTERVAL: usize = 50; // Injects 1,000 PMT packets
    const IDR_INTERVAL: usize = 50; // Injects 1,000 IDR keyframe packets

    println!("\n=== Starting test_stress_malformed_ts_resync_under_load ===");
    println!("Target workload: {TOTAL_VALID_PACKETS} valid packets + continuous corrupted noise");

    let mut synchronizer = TsRingSynchronizer::new();

    // Prepare ground truth packets
    let pat_pkt = build_pat_packet(256);
    let pmt_pkt = build_pmt_packet(256, 257);
    let sps_pkt = build_sps_pps_packet(257);

    // Build the chaotic byte stream containing valid packets interspersed with corrupted noise
    let mut raw_stream = Vec::with_capacity(TOTAL_VALID_PACKETS * TS_PACKET_SIZE * 2);
    let mut expected_pats = 0usize;
    let mut expected_pmts = 0usize;
    let mut expected_idrs = 0usize;
    let mut corrupted_injections = 0usize;

    for i in 0..TOTAL_VALID_PACKETS {
        // 1. Inject Chaos before packet: Truncated packets, bit flips, missing sync bytes, noise
        match i % 7 {
            1 => {
                // Missing sync byte: 188-byte packet with 0x47 replaced by 0x33
                let mut bad_pkt = [0x33u8; TS_PACKET_SIZE];
                let noise = make_non_sync_noise(TS_PACKET_SIZE - 1, i);
                bad_pkt[1..].copy_from_slice(&noise);
                raw_stream.extend_from_slice(&bad_pkt);
                corrupted_injections += 1;
            }
            2 => {
                // Truncated packet: 73 bytes of non-sync garbage
                let noise = make_non_sync_noise(73, i);
                raw_stream.extend_from_slice(&noise);
                corrupted_injections += 1;
            }
            3 => {
                // Corrupted header: Sync byte 0x47 present, but AFC is reserved 0b00
                let mut reserved_afc = [0x00u8; TS_PACKET_SIZE];
                reserved_afc[0] = TS_SYNC_BYTE;
                reserved_afc[1] = 0x01;
                reserved_afc[2] = 0x00;
                reserved_afc[3] = 0x00; // AFC = 00 (reserved!)
                let noise = make_non_sync_noise(TS_PACKET_SIZE - 4, i);
                reserved_afc[4..].copy_from_slice(&noise);
                raw_stream.extend_from_slice(&reserved_afc);
                corrupted_injections += 1;
            }
            4 => {
                // Corrupted adaptation length: af_len = 250 (> 183 bound)
                let mut invalid_af_len = [0x00u8; TS_PACKET_SIZE];
                invalid_af_len[0] = TS_SYNC_BYTE;
                invalid_af_len[1] = 0x01;
                invalid_af_len[2] = 0x00;
                invalid_af_len[3] = 0x30; // AFC = 11 (adaptation + payload)
                invalid_af_len[4] = 250; // exceeds 183!
                let noise = make_non_sync_noise(TS_PACKET_SIZE - 5, i);
                invalid_af_len[5..].copy_from_slice(&noise);
                raw_stream.extend_from_slice(&invalid_af_len);
                corrupted_injections += 1;
            }
            5 => {
                // Random non-sync noise burst (19 bytes)
                let noise = make_non_sync_noise(19, i);
                raw_stream.extend_from_slice(&noise);
                corrupted_injections += 1;
            }
            6 => {
                // Random bit flip on sync byte (0x47 ^ 0x01 = 0x46)
                let mut flipped = [0x00u8; TS_PACKET_SIZE];
                flipped[0] = TS_SYNC_BYTE ^ 0x01;
                let noise = make_non_sync_noise(TS_PACKET_SIZE - 1, i);
                flipped[1..].copy_from_slice(&noise);
                raw_stream.extend_from_slice(&flipped);
                corrupted_injections += 1;
            }
            _ => {}
        }

        // 2. Inject valid critical / media packets
        if i % PAT_INTERVAL == 0 {
            raw_stream.extend_from_slice(&pat_pkt);
            expected_pats += 1;
        } else if i % PMT_INTERVAL == 1 {
            raw_stream.extend_from_slice(&pmt_pkt);
            expected_pmts += 1;
        } else if i % IDR_INTERVAL == 2 {
            raw_stream.extend_from_slice(&sps_pkt);
            let idr = build_idr_packet(257, i as u64);
            raw_stream.extend_from_slice(&idr);
            expected_idrs += 1;
        } else {
            // Normal video P-frame packet (non-IDR slice 0x01)
            let p_frame = build_ts_packet(257, false, None, &[0x00, 0x00, 0x01, 0x01, 0x80]);
            raw_stream.extend_from_slice(&p_frame);
        }
    }

    println!(
        "Total raw stream size: {:.2} MB",
        raw_stream.len() as f64 / 1_048_576.0
    );
    println!(
        "Expected critical frames: PAT={expected_pats}, PMT={expected_pmts}, IDR={expected_idrs}"
    );
    println!("Injected corrupted noise segments: {corrupted_injections}");

    // 3. Feed the raw byte stream in irregular, fragmented slices (testing residue handling)
    let chunk_sizes = [17, 73, 115, 187, 189, 512, 1024, 4096, 7];
    let mut cursor = 0;
    let mut chunk_idx = 0;

    let start_instant = Instant::now();
    let mut extracted_packets = Vec::new();

    while cursor < raw_stream.len() {
        let size = chunk_sizes[chunk_idx % chunk_sizes.len()];
        chunk_idx += 1;
        let end = (cursor + size).min(raw_stream.len());
        let chunk = &raw_stream[cursor..end];
        cursor = end;

        let pkts = synchronizer.push(chunk);
        extracted_packets.extend(pkts);
    }

    let elapsed = start_instant.elapsed();

    // 4. Validate Resynchronization and Recovery Invariants
    let mut recovered_pats = 0usize;
    let mut recovered_pmts = 0usize;
    let mut recovered_idrs = 0usize;
    let mut total_valid_parsed = 0usize;

    for pkt in &extracted_packets {
        assert_eq!(
            pkt.len(),
            TS_PACKET_SIZE,
            "Extracted packet length must be exactly 188"
        );
        assert_eq!(
            pkt[0], TS_SYNC_BYTE,
            "Extracted packet must begin with sync byte 0x47"
        );

        let meta = parse_ts_packet(pkt, Some(256), Some(257));
        if let Some(m) = meta {
            total_valid_parsed += 1;
            if m.is_pat {
                recovered_pats += 1;
                let extracted_pmt = extract_pmt_pid_from_pat(pkt);
                assert_eq!(extracted_pmt, Some(256));
            }
            if m.is_pmt {
                recovered_pmts += 1;
                let extracted_vpid = extract_video_pid_from_pmt(pkt);
                assert_eq!(extracted_vpid, Some(257));
            }
            if m.is_idr {
                recovered_idrs += 1;
            }
        }
    }

    let pkts_per_sec = extracted_packets.len() as f64 / elapsed.as_secs_f64();
    let mb_per_sec = (raw_stream.len() as f64 / 1_048_576.0) / elapsed.as_secs_f64();

    println!("--- Malformed TS Resynchronization Metrics ---");
    println!("Elapsed parser duration: {elapsed:.4?}");
    println!("Parser throughput: {mb_per_sec:.2} MB/s ({pkts_per_sec:.0} packets/sec)");
    println!("Total packets extracted: {}", extracted_packets.len());
    println!("Total valid parsed: {total_valid_parsed}");
    println!("PAT recovery: {recovered_pats}/{expected_pats} (100.0%)");
    println!("PMT recovery: {recovered_pmts}/{expected_pmts} (100.0%)");
    println!("IDR recovery: {recovered_idrs}/{expected_idrs} (100.0%)");

    // Enforce required stress criteria:
    // Throughput >= 50,000 packets/sec
    assert!(
        pkts_per_sec >= 50_000.0,
        "Parser throughput {pkts_per_sec:.0} pkts/sec fell below 50,000 requirement!"
    );

    // 100% recovery of all critical frames
    assert_eq!(
        recovered_pats, expected_pats,
        "PAT frames skipped during resync!"
    );
    assert_eq!(
        recovered_pmts, expected_pmts,
        "PMT frames skipped during resync!"
    );
    assert_eq!(
        recovered_idrs, expected_idrs,
        "IDR keyframes skipped during resync!"
    );

    println!("Status: PASSED (100% recovery, zero panics, exceeded 50,000 pkts/sec threshold)");
}

// ============================================================================
// Test 4: Zapping Burst Latency Under Load (< 2ms)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_zapping_burst_latency_under_load() {
    let _suite_lock = SUITE_MUTEX.lock().await;

    const CAPACITY_BYTES: usize = 16 * 1024 * 1024; // 16 MB ring
    const TOTAL_STREAMING_PACKETS: usize = 50_000;
    const NUM_BURST_PROBES: usize = 1_000;

    println!("\n=== Starting test_stress_zapping_burst_latency_under_load ===");
    println!("Writer workload: {TOTAL_STREAMING_PACKETS} packets at maximum streaming speed");
    println!("Burst probe requests: {NUM_BURST_PROBES} concurrent extractions");

    let ring = Arc::new(TsStreamRing::new(CAPACITY_BYTES));
    let writer_done = Arc::new(AtomicBool::new(false));

    // Prime ring buffer with initial PAT, PMT, SPS/PPS, and IDR so zapping bursts are immediately valid
    let pat = build_pat_packet(256);
    let pmt = build_pmt_packet(256, 257);
    let sps = build_sps_pps_packet(257);
    let idr = build_idr_packet(257, 0);

    ring.ingest_raw(&pat).expect("prime PAT");
    ring.ingest_raw(&pmt).expect("prime PMT");
    ring.ingest_raw(&sps).expect("prime SPS");
    ring.ingest_raw(&idr).expect("prime IDR");

    // 1. Spawn Writer Task: Continuously streams TS packets at full blast
    let ring_writer = ring.clone();
    let writer_done_clone = writer_done.clone();

    let writer_handle = tokio::spawn(async move {
        let pat_data = build_pat_packet(256);
        let pmt_data = build_pmt_packet(256, 257);
        let sps_data = build_sps_pps_packet(257);

        let mut batch = BytesMut::with_capacity(TS_PACKET_SIZE * 7);

        let write_start = Instant::now();
        for seq in 1..=TOTAL_STREAMING_PACKETS {
            batch.clear();

            // Periodic PSI / Keyframe refresh
            if seq % 100 == 0 {
                batch.extend_from_slice(&pat_data);
                batch.extend_from_slice(&pmt_data);
                batch.extend_from_slice(&sps_data);
                let idr_pkt = build_idr_packet(257, seq as u64);
                batch.extend_from_slice(&idr_pkt);
            } else {
                // 7 standard UDP TS packets per batch
                for sub in 0..7 {
                    let pkt = build_ts_packet(
                        257,
                        false,
                        None,
                        &[0x00, 0x00, 0x01, 0x01, (seq & 0xFF) as u8, sub as u8],
                    );
                    batch.extend_from_slice(&pkt);
                }
            }

            ring_writer.ingest_raw(&batch).expect("ingest_raw");

            if seq % 8 == 0 {
                tokio::task::yield_now().await;
            }
        }

        writer_done_clone.store(true, Ordering::Release);
        write_start.elapsed()
    });

    // 2. Measure Zapping Burst Extraction Latency while Writer is Streaming at full speed
    let ring_reader = ring.clone();
    let mut latencies: Vec<Duration> = Vec::with_capacity(NUM_BURST_PROBES);

    let probe_start = Instant::now();
    for _probe in 0..NUM_BURST_PROBES {
        let t0 = Instant::now();
        let burst = ring_reader.get_zapping_burst().expect("zapping burst");
        let elapsed = t0.elapsed();

        latencies.push(elapsed);

        // Invariant: Zapping burst must contain PAT, PMT, SPS/PPS and IDR
        assert!(
            burst.len() >= TS_PACKET_SIZE * 4,
            "Zapping burst too short: {} bytes",
            burst.len()
        );
        assert_eq!(
            burst[0], TS_SYNC_BYTE,
            "Zapping burst must begin with sync byte 0x47"
        );

        // Yield or brief micro-sleep to interleave probes across the writer's streaming lifetime
        tokio::task::yield_now().await;
    }

    let probe_total_duration = probe_start.elapsed();
    let writer_duration = writer_handle.await.expect("writer task");

    // 3. Compute Latency Distribution Metrics
    latencies.sort();
    let min_lat = latencies[0];
    let max_lat = latencies[latencies.len() - 1];
    let p50_lat = latencies[latencies.len() / 2];
    let p90_lat = latencies[(latencies.len() as f64 * 0.90) as usize];
    let p95_lat = latencies[(latencies.len() as f64 * 0.95) as usize];
    let p99_lat = latencies[(latencies.len() as f64 * 0.99) as usize];

    let sum_nanos: u128 = latencies.iter().map(|d| d.as_nanos()).sum();
    let mean_lat = Duration::from_nanos((sum_nanos / latencies.len() as u128) as u64);

    let total_written_bytes = TOTAL_STREAMING_PACKETS * TS_PACKET_SIZE * 7;
    let writer_throughput_mb =
        (total_written_bytes as f64 / 1_048_576.0) / writer_duration.as_secs_f64();

    println!("--- Zapping Burst Latency Under Load Metrics ---");
    println!("Writer throughput during test: {writer_throughput_mb:.2} MB/s");
    println!("Total burst probes: {NUM_BURST_PROBES}");
    println!("Probe duration: {probe_total_duration:.4?}");
    println!("Min latency:    {min_lat:?}");
    println!("Mean latency:   {mean_lat:?}");
    println!("p50 (Median):   {p50_lat:?}");
    println!("p90 latency:    {p90_lat:?}");
    println!("p95 latency:    {p95_lat:?}");
    println!("p99 latency:    {p99_lat:?}");
    println!("Max latency:    {max_lat:?}");

    // Invariant: Verify zapping burst extraction completes in under 2ms
    let max_ceiling = Duration::from_millis(2);
    assert!(
        p99_lat < max_ceiling,
        "p99 zapping burst latency {p99_lat:?} exceeded 2ms ceiling!"
    );
    assert!(
        max_lat < max_ceiling,
        "Max zapping burst latency {max_lat:?} exceeded 2ms ceiling!"
    );

    println!(
        "Status: PASSED (Zapping burst completed strictly under 2ms under heavy write contention)"
    );
}
