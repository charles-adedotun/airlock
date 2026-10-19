use airlock::engine::{
    MpegTsSynchronizer, TS_PACKET_SIZE, TS_SYNC_BYTE, TsStreamRing, extract_pmt_pid_from_pat,
    extract_video_pid_from_pmt, parse_ts_packet,
};

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
            pkt[6..6 + extra.len()].copy_from_slice(&extra);
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

#[test]
fn test_188_byte_packet_alignment_under_fragmented_stream() {
    let mut synchronizer = MpegTsSynchronizer::new();

    // Create 3 valid 188-byte packets
    let p1 = build_ts_packet(101, false, None, b"packet_1_data");
    let p2 = build_ts_packet(102, false, None, b"packet_2_data");
    let p3 = build_ts_packet(103, false, None, b"packet_3_data");

    // Concatenate into a single continuous stream
    let mut combined = Vec::new();
    combined.extend_from_slice(&p1);
    combined.extend_from_slice(&p2);
    combined.extend_from_slice(&p3);

    // Feed to synchronizer in weird fragmented chunks (e.g. 73 bytes, 150 bytes, etc.)
    let mut extracted = Vec::new();
    let chunk_sizes = [73, 115, 42, 200, 136];
    let mut cursor = 0;

    for size in chunk_sizes {
        if cursor >= combined.len() {
            break;
        }
        let end = (cursor + size).min(combined.len());
        let chunk = &combined[cursor..end];
        cursor = end;

        let packets = synchronizer.push(chunk);
        extracted.extend(packets);
    }

    assert_eq!(extracted.len(), 3);
    assert_eq!(&extracted[0][..], &p1[..]);
    assert_eq!(&extracted[1][..], &p2[..]);
    assert_eq!(&extracted[2][..], &p3[..]);
}

#[test]
fn test_resynchronization_after_corrupted_sync_bytes() {
    let mut synchronizer = MpegTsSynchronizer::new();

    let p1 = build_ts_packet(201, false, None, b"valid_packet_1");
    let p2 = build_ts_packet(202, false, None, b"valid_packet_2");

    // Inject 47 bytes of corrupted / non-sync noise, then p1, then 19 bytes of noise, then p2
    let mut noisy_stream = vec![0x33; 47];
    noisy_stream.extend_from_slice(&p1);
    noisy_stream.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    noisy_stream.extend_from_slice(&p2);

    let packets = synchronizer.push(&noisy_stream);
    assert_eq!(packets.len(), 2);
    assert_eq!(&packets[0][..], &p1[..]);
    assert_eq!(&packets[1][..], &p2[..]);
}

#[test]
fn test_pat_and_pmt_pid_extraction() {
    // Synthetic PAT packet (PID 0) pointing to PMT PID 500 (0x01F4)
    let pat_payload = vec![
        0x00, // pointer field
        0x00, // table ID = 0 (PAT)
        0xB0, 0x0D, // section syntax + length (13 bytes)
        0x00, 0x01, // transport stream ID
        0xC1, // current_next
        0x00, // section 0
        0x00, // last section 0
        0x00, 0x01, // program number = 1
        0xE1, 0xF4, // PMT PID = 500 (0x01F4)
    ];
    let pat_pkt = build_ts_packet(0, true, None, &pat_payload);

    let pmt_pid = extract_pmt_pid_from_pat(&pat_pkt);
    assert_eq!(pmt_pid, Some(500));

    // Synthetic PMT packet (PID 500) declaring Video Stream on PID 501 (H.264 = 0x1B)
    let pmt_payload = vec![
        0x00, // pointer field
        0x02, // table ID = 2 (PMT)
        0xB0, 0x12, // section syntax + length (18 bytes)
        0x00, 0x01, // program number 1
        0xC1, // current_next
        0x00, 0x00, // section/last
        0xE1, 0xF4, // PCR PID = 500
        0xF0, 0x00, // program info length = 0
        0x1B, // stream type = H.264
        0xE1, 0xF5, // elementary PID = 501 (0x01F5)
        0xF0, 0x00, // ES info length = 0
    ];
    let pmt_pkt = build_ts_packet(500, true, None, &pmt_payload);

    let video_pid = extract_video_pid_from_pmt(&pmt_pkt);
    assert_eq!(video_pid, Some(501));
}

#[test]
fn test_h264_and_h265_keyframe_detection() {
    // 1. Adaptation field random access indicator
    let af_keyframe = build_ts_packet(501, false, Some((true, vec![])), b"");
    let meta1 = parse_ts_packet(&af_keyframe, Some(500), Some(501)).unwrap();
    assert!(meta1.is_idr);
    assert!(meta1.random_access);

    // 2. H.264 IDR NAL (0x00, 0x00, 0x01, 0x05)
    let h264_idr_payload = [0x00, 0x00, 0x01, 0x05, 0x88, 0x99];
    let h264_idr_pkt = build_ts_packet(501, true, None, &h264_idr_payload);
    let meta2 = parse_ts_packet(&h264_idr_pkt, Some(500), Some(501)).unwrap();
    assert!(meta2.is_idr);

    // 3. H.264 SPS/PPS NAL (0x00, 0x00, 0x01, 0x07 = SPS)
    let h264_sps_payload = [0x00, 0x00, 0x01, 0x07, 0x64, 0x00];
    let h264_sps_pkt = build_ts_packet(501, true, None, &h264_sps_payload);
    let meta3 = parse_ts_packet(&h264_sps_pkt, Some(500), Some(501)).unwrap();
    assert!(meta3.is_sps_pps);
    assert!(!meta3.is_idr);

    // 4. H.265 IDR NAL (NAL type 19: (19 << 1) = 0x26 = 38)
    let h265_idr_payload = [0x00, 0x00, 0x00, 0x01, 0x26, 0x01];
    let h265_idr_pkt = build_ts_packet(501, true, None, &h265_idr_payload);
    let meta4 = parse_ts_packet(&h265_idr_pkt, Some(500), Some(501)).unwrap();
    assert!(meta4.is_idr);
}

#[test]
fn test_zero_holdback_sub_second_zapping_burst() {
    let ring = TsStreamRing::new(1024 * 1024);

    // Ingest PAT
    let pat_payload = vec![
        0x00, 0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xE1, 0x00,
    ];
    let pat = build_ts_packet(0, true, None, &pat_payload);
    ring.ingest_raw(&pat).expect("ingest PAT");

    // Ingest PMT (PID 256)
    let pmt_payload = vec![
        0x00, 0x02, 0xB0, 0x12, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x00, 0xF0, 0x00, 0x1B, 0xE1,
        0x01, 0xF0, 0x00,
    ];
    let pmt = build_ts_packet(256, true, None, &pmt_payload);
    ring.ingest_raw(&pmt).expect("ingest PMT");

    // Ingest SPS/PPS
    let sps = build_ts_packet(257, true, None, &[0x00, 0x00, 0x01, 0x07, 0x64]);
    ring.ingest_raw(&sps).expect("ingest SPS");

    // Ingest IDR keyframe
    let idr = build_ts_packet(257, true, None, &[0x00, 0x00, 0x01, 0x05, 0xFF]);
    ring.ingest_raw(&idr).expect("ingest IDR");

    // Ingest regular non-keyframe packets
    let p_frame1 = build_ts_packet(257, false, None, &[0x00, 0x00, 0x01, 0x01]);
    let p_frame2 = build_ts_packet(257, false, None, &[0x00, 0x00, 0x01, 0x01]);
    ring.ingest_raw(&p_frame1).expect("ingest P1");
    ring.ingest_raw(&p_frame2).expect("ingest P2");

    // Request Sub-Second Zapping Burst
    let burst = ring.get_zapping_burst().expect("zapping burst");

    // Burst must contain:
    // PAT (188) + PMT (188) + SPS (188) + IDR (188) + P1 (188) + P2 (188) = 6 * 188 = 1128 bytes
    assert_eq!(burst.len(), TS_PACKET_SIZE * 6);
    assert_eq!(&burst[..TS_PACKET_SIZE], &pat[..]);
    assert_eq!(&burst[TS_PACKET_SIZE..TS_PACKET_SIZE * 2], &pmt[..]);
    assert_eq!(&burst[TS_PACKET_SIZE * 2..TS_PACKET_SIZE * 3], &sps[..]);
    assert_eq!(&burst[TS_PACKET_SIZE * 3..TS_PACKET_SIZE * 4], &idr[..]);
}
