use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use airlock::moov::{MoovProbeResult, fetch_tail_range, probe_mp4_boxes};

/// Helper to build a minimal ISO-BMFF box: [4 bytes size, 4 bytes type, payload]
fn make_mp4_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = (8 + payload.len()) as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(payload);
    out
}

#[test]
fn test_probe_mp4_faststart_detection() {
    // Construct FastStart MP4: ftyp -> moov -> mdat
    let mut file_head = Vec::new();
    file_head.extend(make_mp4_box(b"ftyp", b"isommp42")); // 16 bytes
    file_head.extend(make_mp4_box(b"moov", &[0x00; 64])); // 72 bytes
    file_head.extend(make_mp4_box(b"mdat", &[0xFF; 256])); // 264 bytes

    let result = probe_mp4_boxes(&file_head);
    match result {
        MoovProbeResult::FastStart {
            moov_offset,
            moov_size,
        } => {
            assert_eq!(moov_offset, 16);
            assert_eq!(moov_size, 72);
        }
        other => panic!("Expected FastStart, got: {other:?}"),
    }
}

#[test]
fn test_probe_mp4_moov_at_end_detection() {
    // Construct Non-FastStart MP4: ftyp -> mdat (moov missing from head window)
    let mut file_head = Vec::new();
    file_head.extend(make_mp4_box(b"ftyp", b"isommp42")); // 16 bytes
    file_head.extend(make_mp4_box(b"mdat", &[0xFF; 1024])); // 1032 bytes

    let result = probe_mp4_boxes(&file_head);
    match result {
        MoovProbeResult::MoovAtEnd { mdat_offset } => {
            assert_eq!(mdat_offset, 16);
        }
        other => panic!("Expected MoovAtEnd, got: {other:?}"),
    }
}

/// Verifies that MP4 files with tail-end `moov` atoms trigger the out-of-band
/// tail Range probe (`bytes=-2MB` or `bytes=-N`) and initialize immediately
/// without waiting for full sequential download.
#[tokio::test]
async fn test_tail_moov_range_probe_initializes_immediately() {
    let mock_server = MockServer::start().await;

    // Upstream has a 2 GB file where `moov` is located in the final 2048 bytes
    let simulated_moov_atom = make_mp4_box(b"moov", b"track_metadata_index_offsets");

    // WireMock expects an out-of-band suffix Range request: Range: bytes=-2048
    Mock::given(method("GET"))
        .and(path("/vod/large_movie.mp4"))
        .and(header("Range", "bytes=-2048"))
        .respond_with(
            ResponseTemplate::new(206)
                .set_body_bytes(simulated_moov_atom.clone())
                .insert_header("Content-Range", "bytes 2147481599-2147483647/2147483648")
                .insert_header("Content-Length", format!("{}", simulated_moov_atom.len())),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // 1. Initial head read detects `moov` is missing and located at the tail
    let mut head_bytes = Vec::new();
    head_bytes.extend(make_mp4_box(b"ftyp", b"isommp42"));
    head_bytes.extend(make_mp4_box(b"mdat", &[0xAA; 512]));

    let probe = probe_mp4_boxes(&head_bytes);
    assert!(matches!(probe, MoovProbeResult::MoovAtEnd { .. }));

    // 2. Trigger the out-of-band suffix Range probe to fetch the tail 2048 bytes
    let client = reqwest::Client::new();
    let upstream_url = format!("{}/vod/large_movie.mp4", mock_server.uri());

    let start_probe = std::time::Instant::now();
    let tail_bytes = fetch_tail_range(&client, &upstream_url, 2048)
        .await
        .expect("tail probe succeeds");
    let probe_elapsed = start_probe.elapsed();

    // Verify metadata was retrieved immediately in < 100ms without reading 2GB of mdat
    assert!(
        probe_elapsed < std::time::Duration::from_millis(100),
        "Tail probe took {probe_elapsed:?}, expected < 100ms!"
    );

    // Verify the retrieved tail bytes contain the `moov` atom header
    assert!(tail_bytes.len() >= 8);
    assert_eq!(&tail_bytes[4..8], b"moov");

    // Verify internal parser can now parse the retrieved moov box
    let tail_probe = probe_mp4_boxes(&tail_bytes);
    match tail_probe {
        MoovProbeResult::FastStart { moov_size, .. } => {
            assert_eq!(moov_size, simulated_moov_atom.len());
        }
        other => panic!("Expected moov atom in tail payload, got: {other:?}"),
    }
}
