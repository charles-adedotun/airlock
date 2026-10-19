#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use airlock::engine::{
    HlsPlaylistGenerator, HlsSegment, HlsVariant, TS_PACKET_SIZE, TS_SYNC_BYTE, TimeshiftConfig,
    TimeshiftRecorder, TsStreamRing,
};

/// Helper to create a synthetic 188-byte MPEG-TS packet.
fn make_test_packet(pid: u16, is_keyframe: bool) -> [u8; TS_PACKET_SIZE] {
    let mut p = [0u8; TS_PACKET_SIZE];
    p[0] = TS_SYNC_BYTE;
    p[1] = ((pid >> 8) as u8) & 0x1F;
    p[2] = (pid & 0xFF) as u8;

    if is_keyframe {
        // AFC = 0b11 (adaptation + payload), length 1, flag 0x40 (random access / keyframe)
        p[3] = 0x30;
        p[4] = 1;
        p[5] = 0x40;
        // Inject H.264 IDR NAL: 0x00, 0x00, 0x01, 0x65
        p[6] = 0x00;
        p[7] = 0x00;
        p[8] = 0x01;
        p[9] = 0x65;
    } else {
        // AFC = 0b01 (payload only)
        p[3] = 0x10;
        p[4] = 0xAA;
    }

    p
}

/// Helper to generate a unique temporary test directory.
fn make_temp_dir(tag: &str) -> Result<PathBuf, std::io::Error> {
    let base = std::env::temp_dir().join(format!(
        "airlock_test_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

#[tokio::test]
async fn test_timeshift_segment_creation_and_keyframe_slicing()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = make_temp_dir("slice")?;
    let config = TimeshiftConfig::new(&temp_dir, "stream_live1")
        .with_segment_duration(Duration::from_millis(50))
        .with_max_segment_duration(Duration::from_millis(200));

    let recorder = TimeshiftRecorder::new(config)?;

    let pkt_normal = make_test_packet(256, false);
    let pkt_key = make_test_packet(256, true);

    // Ingest first packet (starts segment 0)
    recorder.ingest_packet(&pkt_normal, false).await?;

    // Wait until target segment duration has elapsed
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Ingest keyframe packet -> should slice segment 0 and start segment 1
    recorder.ingest_packet(&pkt_key, true).await?;

    // Flush and force rotate current active segment to finalize segment 1
    let seg1_opt = recorder.force_rotate().await?;
    assert!(
        seg1_opt.is_some(),
        "Segment 1 should be finalized on force_rotate"
    );

    let segments = recorder.segments();
    assert_eq!(segments.len(), 2, "Expected 2 segments (seg 0 and seg 1)");

    assert_eq!(segments[0].sequence, 0);
    assert_eq!(segments[1].sequence, 1);

    // Verify files exist on disk
    assert!(
        segments[0].file_path.exists(),
        "seg_0.ts must exist on disk"
    );
    assert!(
        segments[1].file_path.exists(),
        "seg_1.ts must exist on disk"
    );

    // Verify byte lengths
    assert_eq!(segments[0].byte_length, TS_PACKET_SIZE as u64);
    assert_eq!(segments[1].byte_length, TS_PACKET_SIZE as u64);

    // Verify page cache drop count
    assert!(
        recorder.fadvise_drop_count() >= 2,
        "posix_fadvise_dontneed_fd should have been called on both completed segments"
    );

    // Clean up
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    Ok(())
}

#[tokio::test]
async fn test_timeshift_max_segments_rollover_and_unlinking()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = make_temp_dir("rollover")?;
    let config = TimeshiftConfig::new(&temp_dir, "stream_roll")
        .with_segment_duration(Duration::from_millis(10))
        .with_max_segments(3);

    let recorder = TimeshiftRecorder::new(config)?;
    let pkt = make_test_packet(100, false);

    let mut created_paths = Vec::new();

    // Create 5 segments: seq 0, 1, 2, 3, 4
    for _ in 0..5 {
        recorder.ingest_packet(&pkt, false).await?;
        let finalized = recorder.force_rotate().await?;
        if let Some(seg) = finalized {
            created_paths.push(seg.file_path);
        }
    }

    assert_eq!(created_paths.len(), 5);

    // Max segments is 3, so index should only contain 3 segments: 2, 3, 4
    let current_segments = recorder.segments();
    assert_eq!(
        current_segments.len(),
        3,
        "Only 3 segments should remain in index"
    );
    assert_eq!(current_segments[0].sequence, 2);
    assert_eq!(current_segments[1].sequence, 3);
    assert_eq!(current_segments[2].sequence, 4);

    // Verify seg 0 and seg 1 were unlinked from disk
    assert!(
        !created_paths[0].exists(),
        "seg_0.ts must be unlinked from disk"
    );
    assert!(
        !created_paths[1].exists(),
        "seg_1.ts must be unlinked from disk"
    );

    // Verify seg 2, 3, 4 still exist on disk
    assert!(created_paths[2].exists(), "seg_2.ts must remain on disk");
    assert!(created_paths[3].exists(), "seg_3.ts must remain on disk");
    assert!(created_paths[4].exists(), "seg_4.ts must remain on disk");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    Ok(())
}

#[tokio::test]
async fn test_timeshift_disk_quota_eviction() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = make_temp_dir("quota")?;
    // Quota of 500 bytes allows at most 2 packets (188 * 2 = 376 < 500; 376 + 188 = 564 > 500)
    let config = TimeshiftConfig::new(&temp_dir, "stream_quota")
        .with_segment_duration(Duration::from_millis(10))
        .with_max_disk_bytes(500);

    let recorder = TimeshiftRecorder::new(config)?;
    let pkt = make_test_packet(200, false);

    let mut paths = Vec::new();
    for _ in 0..4 {
        recorder.ingest_packet(&pkt, false).await?;
        if let Some(seg) = recorder.force_rotate().await? {
            paths.push(seg.file_path);
        }
    }

    assert_eq!(paths.len(), 4);
    assert!(
        recorder.total_disk_bytes() <= 500,
        "Total disk bytes must not exceed quota of 500"
    );

    // Oldest segment(s) must have been evicted and unlinked
    assert!(
        !paths[0].exists(),
        "Oldest segment must be evicted from disk"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    Ok(())
}

#[tokio::test]
async fn test_timeshift_seeking_and_reading() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = make_temp_dir("seek")?;
    let config = TimeshiftConfig::new(&temp_dir, "stream_seek")
        .with_segment_duration(Duration::from_millis(10));

    let recorder = TimeshiftRecorder::new(config)?;
    let pkt = make_test_packet(300, false);

    let before_time = SystemTime::now();
    tokio::time::sleep(Duration::from_millis(5)).await;

    recorder.ingest_packet(&pkt, false).await?;
    let seg0 = recorder
        .force_rotate()
        .await?
        .ok_or("Failed to finalize seg0")?;

    tokio::time::sleep(Duration::from_millis(5)).await;
    recorder.ingest_packet(&pkt, false).await?;
    let seg1 = recorder
        .force_rotate()
        .await?
        .ok_or("Failed to finalize seg1")?;

    // Seek by sequence
    let found0 = recorder.seek_by_sequence(0);
    assert!(found0.is_some());
    assert_eq!(found0.as_ref().map(|s| s.sequence), Some(0));

    let found1 = recorder.seek_by_sequence(1);
    assert!(found1.is_some());
    assert_eq!(found1.as_ref().map(|s| s.sequence), Some(1));

    let found_missing = recorder.seek_by_sequence(999);
    assert!(found_missing.is_none());

    // Read bytes
    let bytes0 = recorder.read_segment_bytes(0).await?;
    assert_eq!(bytes0.len(), TS_PACKET_SIZE);
    assert_eq!(bytes0[0], TS_SYNC_BYTE);

    // Open file
    let file1 = recorder.open_segment_file(1).await?;
    let meta = file1.metadata().await?;
    assert_eq!(meta.len(), TS_PACKET_SIZE as u64);

    // Seek by timestamp
    let found_by_ts = recorder.seek_by_timestamp(seg0.start_timestamp);
    assert!(found_by_ts.is_some());
    assert_eq!(found_by_ts.as_ref().map(|s| s.sequence), Some(0));

    let found_by_ts1 = recorder.seek_by_timestamp(seg1.start_timestamp);
    assert!(found_by_ts1.is_some());
    assert_eq!(found_by_ts1.as_ref().map(|s| s.sequence), Some(1));

    // Seek closest timestamp
    let closest = recorder.seek_closest_by_timestamp(before_time);
    assert!(closest.is_some());
    assert_eq!(closest.as_ref().map(|s| s.sequence), Some(0));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    Ok(())
}

#[test]
fn test_hls_playlist_sliding_window_tags_and_sequence() {
    let generator = HlsPlaylistGenerator::new()
        .with_window_size(3)
        .with_target_duration(6);

    let segments = vec![
        HlsSegment::new(10, Duration::from_secs(6), "seg_10.ts"),
        HlsSegment::new(11, Duration::from_secs(6), "seg_11.ts"),
        HlsSegment::new(12, Duration::from_secs(6), "seg_12.ts"),
        HlsSegment::new(13, Duration::from_secs(6), "seg_13.ts"),
        HlsSegment::new(14, Duration::from_secs(6), "seg_14.ts"),
    ];

    // Using window size 3 with 5 items takes the last 3: seq 12, 13, 14
    let playlist = generator.generate_from_segments(&segments[2..]);

    assert!(playlist.starts_with("#EXTM3U\n"));
    assert!(playlist.contains("#EXT-X-VERSION:3\n"));
    assert!(playlist.contains("#EXT-X-TARGETDURATION:6\n"));
    assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:12\n"));

    // Verify segments listed
    assert!(playlist.contains("#EXTINF:6.000000,\nseg_12.ts\n"));
    assert!(playlist.contains("#EXTINF:6.000000,\nseg_13.ts\n"));
    assert!(playlist.contains("#EXTINF:6.000000,\nseg_14.ts\n"));

    // Sliding window live playlists must NOT have #EXT-X-ENDLIST
    assert!(!playlist.contains("#EXT-X-ENDLIST"));
}

#[tokio::test]
async fn test_hls_playlist_generation_from_timeshift_recorder()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = make_temp_dir("hls_gen")?;
    let config = TimeshiftConfig::new(&temp_dir, "hls_stream")
        .with_segment_duration(Duration::from_millis(10));

    let recorder = TimeshiftRecorder::new(config)?;
    let pkt = make_test_packet(256, false);

    // Ingest and rotate 4 segments
    for _ in 0..4 {
        recorder.ingest_packet(&pkt, false).await?;
        let _ = recorder.force_rotate().await?;
    }

    let generator = HlsPlaylistGenerator::new()
        .with_window_size(3)
        .with_uri_prefix("/api/timeshift/hls_stream");

    let playlist = generator.generate_from_timeshift(&recorder);

    assert!(playlist.starts_with("#EXTM3U\n"));
    assert!(playlist.contains("#EXT-X-VERSION:3\n"));
    assert!(playlist.contains("#EXT-X-TARGETDURATION:6\n"));
    // With 4 segments (0, 1, 2, 3) and window size 3, window contains 1, 2, 3 -> sequence 1
    assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:1\n"));

    assert!(playlist.contains("/api/timeshift/hls_stream/seg_1.ts\n"));
    assert!(playlist.contains("/api/timeshift/hls_stream/seg_2.ts\n"));
    assert!(playlist.contains("/api/timeshift/hls_stream/seg_3.ts\n"));
    assert!(!playlist.contains("seg_0.ts"));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    Ok(())
}

#[test]
fn test_hls_playlist_generation_from_ts_ring() -> Result<(), Box<dyn std::error::Error>> {
    let ring = TsStreamRing::new(1024 * 1024);
    let idr_pkt = make_test_packet(256, true);
    let norm_pkt = make_test_packet(256, false);

    // Ingest chunks containing keyframes
    ring.ingest_raw(&idr_pkt)?;
    ring.ingest_raw(&norm_pkt)?;
    ring.ingest_raw(&idr_pkt)?;
    ring.ingest_raw(&norm_pkt)?;

    let generator = HlsPlaylistGenerator::new().with_window_size(5);
    let playlist = generator.generate_from_ts_ring(&ring, "/api/stream/live1")?;

    assert!(playlist.starts_with("#EXTM3U\n"));
    assert!(playlist.contains("#EXT-X-VERSION:3\n"));
    assert!(playlist.contains("#EXT-X-TARGETDURATION:6\n"));
    assert!(playlist.contains("/api/stream/live1/ring_seg_"));

    Ok(())
}

#[test]
fn test_hls_master_multivariant_playlist() {
    let variants = vec![
        HlsVariant {
            uri: "1080p/index.m3u8".to_string(),
            bandwidth: 6_000_000,
            resolution: Some((1920, 1080)),
            codecs: Some("avc1.640028,mp4a.40.2".to_string()),
            name: Some("1080p60".to_string()),
        },
        HlsVariant {
            uri: "720p/index.m3u8".to_string(),
            bandwidth: 3_000_000,
            resolution: Some((1280, 720)),
            codecs: Some("avc1.4d401f,mp4a.40.2".to_string()),
            name: Some("720p".to_string()),
        },
    ];

    let master = HlsPlaylistGenerator::generate_master_playlist(&variants);

    assert!(master.starts_with("#EXTM3U\n"));
    assert!(master.contains("#EXT-X-VERSION:3\n"));
    assert!(master.contains("#EXT-X-STREAM-INF:BANDWIDTH=6000000,RESOLUTION=1920x1080,CODECS=\"avc1.640028,mp4a.40.2\",NAME=\"1080p60\"\n1080p/index.m3u8\n"));
    assert!(master.contains("#EXT-X-STREAM-INF:BANDWIDTH=3000000,RESOLUTION=1280x720,CODECS=\"avc1.4d401f,mp4a.40.2\",NAME=\"720p\"\n720p/index.m3u8\n"));
}
