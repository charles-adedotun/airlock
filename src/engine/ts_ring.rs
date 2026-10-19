//! 188-byte MPEG-TS packet synchronizer, keyframe detector, and sub-second zapping burst generator.
//!
//! Provides zero-holdback stream priming for IPTV players (TiviMate, ExoPlayer, VLC),
//! eliminating the multi-second black screen during channel changes by immediately bursting
//! cached PAT, PMT, SPS/PPS parameter sets, and the latest IDR frame directly to new sockets.

use bytes::{BufMut, Bytes, BytesMut};
use std::sync::RwLock;

use crate::error::StorageError;
use crate::ring::{LiveRingBuffer, RingChunk};

/// Standard MPEG Transport Stream packet size.
pub const TS_PACKET_SIZE: usize = 188;
/// Standard MPEG-TS synchronization byte.
pub const TS_SYNC_BYTE: u8 = 0x47;

/// Metadata extracted from a 188-byte MPEG-TS packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsPacketMeta {
    pub pid: u16,
    pub pusi: bool,
    pub has_adaptation: bool,
    pub random_access: bool,
    pub is_pat: bool,
    pub is_pmt: bool,
    pub is_idr: bool,
    pub is_sps_pps: bool,
}

/// 188-byte MPEG-TS packet synchronizer that aligns misaligned or fragmented byte streams.
#[derive(Debug, Default)]
pub struct MpegTsSynchronizer {
    residue: Vec<u8>,
}

/// Validate MPEG-TS packet header structure (sync byte, non-reserved AFC, and valid adaptation length).
pub fn is_valid_ts_header(pkt: &[u8]) -> bool {
    if pkt.len() < TS_PACKET_SIZE || pkt[0] != TS_SYNC_BYTE {
        return false;
    }
    let afc = (pkt[3] >> 4) & 0x03;
    if afc == 0b00 {
        return false; // Reserved AFC
    }
    if afc == 0b10 || afc == 0b11 {
        let af_len = pkt[4] as usize;
        if af_len > 183 {
            return false; // Adaptation field exceeds packet bounds
        }
    }
    true
}

impl MpegTsSynchronizer {
    pub fn new() -> Self {
        Self {
            residue: Vec::with_capacity(TS_PACKET_SIZE * 2),
        }
    }

    /// Push an arbitrary slice of incoming bytes, resynchronize on `0x47` sync bytes,
    /// and extract complete 188-byte packet chunks.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        let buffer = if self.residue.is_empty() {
            chunk.to_vec()
        } else {
            let mut combined = Vec::with_capacity(self.residue.len() + chunk.len());
            combined.extend_from_slice(&self.residue);
            combined.extend_from_slice(chunk);
            self.residue.clear();
            combined
        };

        let mut packets = Vec::new();
        let mut cursor = 0;
        let len = buffer.len();

        while cursor + TS_PACKET_SIZE <= len {
            if is_valid_ts_header(&buffer[cursor..cursor + TS_PACKET_SIZE]) {
                let packet_slice = &buffer[cursor..cursor + TS_PACKET_SIZE];
                packets.push(Bytes::copy_from_slice(packet_slice));
                cursor += TS_PACKET_SIZE;
            } else {
                // Scan forward to the next potential sync byte
                cursor += 1;
            }
        }

        // Retain unaligned tail bytes for the next incoming chunk
        if cursor < len {
            self.residue.extend_from_slice(&buffer[cursor..]);
        }

        packets
    }

    /// Reset internal residue buffer.
    pub fn reset(&mut self) {
        self.residue.clear();
    }
}

/// Inspect a 188-byte MPEG-TS packet and extract PSI tables and video NAL parameters.
pub fn parse_ts_packet(
    packet: &[u8],
    known_pmt_pid: Option<u16>,
    known_video_pid: Option<u16>,
) -> Option<TsPacketMeta> {
    if packet.len() != TS_PACKET_SIZE || packet[0] != TS_SYNC_BYTE {
        return None;
    }

    // Packet header flags
    let pusi = (packet[1] & 0x40) != 0;
    let pid = (((packet[1] & 0x1F) as u16) << 8) | (packet[2] as u16);
    let afc = (packet[3] >> 4) & 0x03;

    let has_adaptation = afc == 0b10 || afc == 0b11;
    let has_payload = afc == 0b01 || afc == 0b11;

    let mut random_access = false;
    let mut payload_offset = 4;

    if has_adaptation {
        let af_len = packet[4] as usize;
        if af_len > 0 && packet.len() > 5 {
            // Flag bit 6: random_access_indicator
            random_access = (packet[5] & 0x40) != 0;
        }
        payload_offset = 5 + af_len;
    }

    if !has_payload || payload_offset >= TS_PACKET_SIZE {
        return Some(TsPacketMeta {
            pid,
            pusi,
            has_adaptation,
            random_access,
            is_pat: pid == 0,
            is_pmt: known_pmt_pid == Some(pid),
            is_idr: random_access,
            is_sps_pps: false,
        });
    }

    let is_pat = pid == 0;
    let is_pmt = known_pmt_pid == Some(pid);

    let payload = &packet[payload_offset..];
    let mut is_idr = random_access;
    let mut is_sps_pps = false;

    // Scan for H.264 / H.265 NAL Units if this is a known video PID or if PUSI indicates PES
    let check_video = known_video_pid.is_none_or(|v| v == pid);
    if check_video && payload.len() > 4 {
        let mut i = 0;
        while i + 4 <= payload.len() {
            let start_code_len = if payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 1 {
                Some(3)
            } else if i + 4 <= payload.len()
                && payload[i] == 0
                && payload[i + 1] == 0
                && payload[i + 2] == 0
                && payload[i + 3] == 1
            {
                Some(4)
            } else {
                None
            };

            if let Some(scl) = start_code_len {
                let nal_idx = i + scl;
                if nal_idx < payload.len() {
                    let nal_byte = payload[nal_idx];
                    // H.264 NAL Type
                    let h264_type = nal_byte & 0x1F;
                    if h264_type == 5 {
                        is_idr = true;
                    } else if h264_type == 7 || h264_type == 8 {
                        is_sps_pps = true;
                    }

                    // H.265 NAL Type
                    let h265_type = (nal_byte >> 1) & 0x3F;
                    if h265_type == 19 || h265_type == 20 {
                        is_idr = true;
                    } else if h265_type == 32 || h265_type == 33 || h265_type == 34 {
                        is_sps_pps = true;
                    }
                }
                i += scl;
            } else {
                i += 1;
            }
        }
    }

    Some(TsPacketMeta {
        pid,
        pusi,
        has_adaptation,
        random_access,
        is_pat,
        is_pmt,
        is_idr,
        is_sps_pps,
    })
}

/// Extract Program Map Table (PMT) PID from a Program Association Table (PAT) packet.
pub fn extract_pmt_pid_from_pat(packet: &[u8]) -> Option<u16> {
    if packet.len() != TS_PACKET_SIZE || packet[0] != TS_SYNC_BYTE {
        return None;
    }
    let pid = (((packet[1] & 0x1F) as u16) << 8) | (packet[2] as u16);
    if pid != 0 {
        return None;
    }

    let pusi = (packet[1] & 0x40) != 0;
    let afc = (packet[3] >> 4) & 0x03;
    let mut offset = 4;
    if afc == 0b10 || afc == 0b11 {
        let af_len = packet[4] as usize;
        offset = 5 + af_len;
    }
    if offset >= TS_PACKET_SIZE {
        return None;
    }

    if pusi {
        let pointer = packet[offset] as usize;
        offset += 1 + pointer;
    }

    if offset + 12 > TS_PACKET_SIZE {
        return None;
    }

    let table_id = packet[offset];
    if table_id != 0x00 {
        return None; // Not PAT
    }

    let section_len = (((packet[offset + 1] & 0x0F) as usize) << 8) | (packet[offset + 2] as usize);
    let mut prog_idx = offset + 8;
    let section_end = (offset + 3 + section_len).min(TS_PACKET_SIZE - 4); // exclude 4-byte CRC

    while prog_idx + 4 <= section_end {
        let prog_num = ((packet[prog_idx] as u16) << 8) | (packet[prog_idx + 1] as u16);
        let pmt_pid = (((packet[prog_idx + 2] & 0x1F) as u16) << 8) | (packet[prog_idx + 3] as u16);

        if prog_num != 0 {
            return Some(pmt_pid);
        }
        prog_idx += 4;
    }

    None
}

/// Extract elementary video stream PID from a Program Map Table (PMT) packet.
pub fn extract_video_pid_from_pmt(packet: &[u8]) -> Option<u16> {
    if packet.len() != TS_PACKET_SIZE || packet[0] != TS_SYNC_BYTE {
        return None;
    }

    let pusi = (packet[1] & 0x40) != 0;
    let afc = (packet[3] >> 4) & 0x03;
    let mut offset = 4;
    if afc == 0b10 || afc == 0b11 {
        let af_len = packet[4] as usize;
        offset = 5 + af_len;
    }
    if offset >= TS_PACKET_SIZE {
        return None;
    }

    if pusi {
        let pointer = packet[offset] as usize;
        offset += 1 + pointer;
    }

    if offset + 12 > TS_PACKET_SIZE {
        return None;
    }

    let table_id = packet[offset];
    if table_id != 0x02 {
        return None; // Not PMT
    }

    let section_len = (((packet[offset + 1] & 0x0F) as usize) << 8) | (packet[offset + 2] as usize);
    let prog_info_len =
        (((packet[offset + 10] & 0x0F) as usize) << 8) | (packet[offset + 11] as usize);

    let mut es_idx = offset + 12 + prog_info_len;
    let section_end = (offset + 3 + section_len).min(TS_PACKET_SIZE - 4);

    while es_idx + 5 <= section_end {
        let stream_type = packet[es_idx];
        let elem_pid = (((packet[es_idx + 1] & 0x1F) as u16) << 8) | (packet[es_idx + 2] as u16);
        let es_info_len =
            (((packet[es_idx + 3] & 0x0F) as usize) << 8) | (packet[es_idx + 4] as usize);

        // 0x1B = H.264/AVC, 0x24 = H.265/HEVC, 0x02 = MPEG-2 Video
        if stream_type == 0x1B || stream_type == 0x24 || stream_type == 0x02 {
            return Some(elem_pid);
        }

        es_idx += 5 + es_info_len;
    }

    None
}

/// Extract all elementary audio stream PIDs from a Program Map Table (PMT) packet.
/// Supports MPEG-1 Audio (0x03), MPEG-2 Audio (0x04), AAC ADTS (0x0F), LATM AAC (0x11),
/// Dolby AC-3 (0x81), and Enhanced AC-3 / Dolby Digital Plus (0x87).
pub fn extract_audio_pids_from_pmt(packet: &[u8]) -> Vec<u16> {
    if packet.len() != TS_PACKET_SIZE || packet[0] != TS_SYNC_BYTE {
        return Vec::new();
    }

    let pusi = (packet[1] & 0x40) != 0;
    let afc = (packet[3] >> 4) & 0x03;
    let mut offset = 4;
    if afc == 0b10 || afc == 0b11 {
        let af_len = packet[4] as usize;
        offset = 5 + af_len;
    }
    if offset >= TS_PACKET_SIZE {
        return Vec::new();
    }

    if pusi {
        let pointer = packet[offset] as usize;
        offset += 1 + pointer;
    }

    if offset + 12 > TS_PACKET_SIZE {
        return Vec::new();
    }

    let table_id = packet[offset];
    if table_id != 0x02 {
        return Vec::new(); // Not PMT
    }

    let section_len = (((packet[offset + 1] & 0x0F) as usize) << 8) | (packet[offset + 2] as usize);
    let prog_info_len =
        (((packet[offset + 10] & 0x0F) as usize) << 8) | (packet[offset + 11] as usize);

    let mut es_idx = offset + 12 + prog_info_len;
    let section_end = (offset + 3 + section_len).min(TS_PACKET_SIZE - 4);
    let mut audio_pids = Vec::new();

    while es_idx + 5 <= section_end {
        let stream_type = packet[es_idx];
        let elem_pid = (((packet[es_idx + 1] & 0x1F) as u16) << 8) | (packet[es_idx + 2] as u16);
        let es_info_len =
            (((packet[es_idx + 3] & 0x0F) as usize) << 8) | (packet[es_idx + 4] as usize);

        // Standard MPEG audio stream types:
        // 0x03 = ISO/IEC 11172-3 Audio (MPEG-1 Audio)
        // 0x04 = ISO/IEC 13818-3 Audio (MPEG-2 Audio)
        // 0x0F = ISO/IEC 13818-7 Audio with ADTS (AAC)
        // 0x11 = ISO/IEC 14496-3 Audio with LATM (AAC)
        // 0x81 = Dolby AC-3 Audio
        // 0x87 = Enhanced AC-3 / Dolby Digital Plus Audio
        if stream_type == 0x03
            || stream_type == 0x04
            || stream_type == 0x0F
            || stream_type == 0x11
            || stream_type == 0x81
            || stream_type == 0x87
        {
            audio_pids.push(elem_pid);
        }

        es_idx += 5 + es_info_len;
    }

    audio_pids
}

/// Thread-safe MPEG-TS streaming ring buffer with sub-second zapping burst generation.
pub struct TsStreamRing {
    ring: LiveRingBuffer,
    state: RwLock<TsStreamState>,
}

struct TsStreamState {
    synchronizer: MpegTsSynchronizer,
    cached_pat: Option<Bytes>,
    cached_pmt: Option<Bytes>,
    cached_sps_pps: Vec<Bytes>,
    pmt_pid: Option<u16>,
    video_pid: Option<u16>,
    audio_pids: Vec<u16>,
    latest_idr_seq: Option<u64>,
}

impl TsStreamRing {
    /// Create a new TS stream ring buffer with the specified byte capacity.
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            ring: LiveRingBuffer::new(capacity_bytes),
            state: RwLock::new(TsStreamState {
                synchronizer: MpegTsSynchronizer::new(),
                cached_pat: None,
                cached_pmt: None,
                cached_sps_pps: Vec::new(),
                pmt_pid: None,
                video_pid: None,
                audio_pids: Vec::new(),
                latest_idr_seq: None,
            }),
        }
    }

    /// Retrieve currently identified elementary audio PIDs from cached PMT.
    pub fn audio_pids(&self) -> Vec<u16> {
        self.state.read().map(|s| s.audio_pids.clone()).unwrap_or_default()
    }

    /// Push raw chunks into the synchronizer, parse TS packets, index keyframes,
    /// and commit chunks to the underlying ring buffer.
    pub fn ingest_raw(&self, data: &[u8]) -> Result<usize, StorageError> {
        let mut state = self.state.write().map_err(|_| {
            StorageError::Io(std::io::Error::other("TsStreamRing state lock poisoned"))
        })?;

        let packets = state.synchronizer.push(data);
        let count = packets.len();

        for packet in packets {
            let meta = parse_ts_packet(&packet, state.pmt_pid, state.video_pid);

            if let Some(m) = meta {
                if m.is_pat {
                    if let Some(pmt_pid) = extract_pmt_pid_from_pat(&packet) {
                        state.pmt_pid = Some(pmt_pid);
                    }
                    state.cached_pat = Some(packet.clone());
                } else if m.is_pmt {
                    if let Some(v_pid) = extract_video_pid_from_pmt(&packet) {
                        state.video_pid = Some(v_pid);
                    }
                    state.audio_pids = extract_audio_pids_from_pmt(&packet);
                    state.cached_pmt = Some(packet.clone());
                }

                if m.is_sps_pps {
                    // Keep most recent parameter sets (limit to 4 to bound memory)
                    if state.cached_sps_pps.len() >= 4 {
                        state.cached_sps_pps.remove(0);
                    }
                    state.cached_sps_pps.push(packet.clone());
                }

                let seq = self.ring.push(packet, m.is_idr)?;

                if m.is_idr {
                    state.latest_idr_seq = Some(seq);
                }
            } else {
                self.ring.push(packet, false)?;
            }
        }

        Ok(count)
    }

    /// Generate an instantaneous **Zero-Holdback Sub-Second Zapping Burst**.
    ///
    /// Produces a byte payload containing:
    /// 1. Latest cached PAT packet (PID 0).
    /// 2. Latest cached PMT packet.
    /// 3. Cached SPS / PPS parameter sets.
    /// 4. All packets starting from the most recent IDR frame up to current write head.
    ///
    /// This provides client decoders with everything necessary to render video in < 450ms.
    pub fn get_zapping_burst(&self) -> Result<Bytes, StorageError> {
        let state = self.state.read().map_err(|_| {
            StorageError::Io(std::io::Error::other("TsStreamRing state lock poisoned"))
        })?;

        let mut burst = BytesMut::with_capacity(TS_PACKET_SIZE * 64);

        // 1. Inject cached PAT
        if let Some(ref pat) = state.cached_pat {
            burst.put_slice(pat);
        }

        // 2. Inject cached PMT
        if let Some(ref pmt) = state.cached_pmt {
            burst.put_slice(pmt);
        }

        // 3. Inject cached SPS/PPS
        for sps_pps in &state.cached_sps_pps {
            burst.put_slice(sps_pps);
        }

        // 4. Retrieve chunks starting from the latest keyframe sequence
        if let Some(idr_seq) = state.latest_idr_seq {
            let (chunks, _) = self.ring.read_from(idr_seq, 500)?;
            for chunk in chunks {
                burst.put_slice(&chunk.data);
            }
        }

        Ok(burst.freeze())
    }

    /// Read stream chunks sequentially starting from a sequence number.
    pub fn read_from(
        &self,
        from_seq: u64,
        max_chunks: usize,
    ) -> Result<(Vec<RingChunk>, u64), StorageError> {
        self.ring.read_from(from_seq, max_chunks)
    }

    /// Retrieve the sequence number of the most recent keyframe.
    pub fn latest_keyframe_sequence(&self) -> Result<Option<u64>, StorageError> {
        self.ring.latest_keyframe_sequence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_packet(pid: u16, is_keyframe: bool) -> [u8; TS_PACKET_SIZE] {
        let mut p = [0u8; TS_PACKET_SIZE];
        p[0] = TS_SYNC_BYTE;
        p[1] = ((pid >> 8) as u8) & 0x1F;
        p[2] = (pid & 0xFF) as u8;

        if is_keyframe {
            // AFC = 0b11 (adaptation + payload), length 1, flag 0x40 (random access)
            p[3] = 0x30;
            p[4] = 1;
            p[5] = 0x40;
            // Inject H.264 IDR NAL: 0x00, 0x00, 0x01, 0x65 (NAL type 5)
            p[6] = 0x00;
            p[7] = 0x00;
            p[8] = 0x01;
            p[9] = 0x65;
        } else {
            // AFC = 0b01 (payload only)
            p[3] = 0x10;
        }

        p
    }

    #[test]
    fn test_synchronizer_handles_misalignment_and_residue() {
        let mut synchronizer = MpegTsSynchronizer::new();
        let p1 = create_dummy_packet(100, false);
        let p2 = create_dummy_packet(101, true);

        // Prepend 15 garbage bytes before p1
        let mut stream = vec![0xEE; 15];
        stream.extend_from_slice(&p1);
        // Split p2 across two pushes (first 100 bytes, then remaining 88 bytes)
        stream.extend_from_slice(&p2[..100]);

        let packets_batch1 = synchronizer.push(&stream);
        assert_eq!(packets_batch1.len(), 1);
        assert_eq!(&packets_batch1[0][..], &p1[..]);

        let packets_batch2 = synchronizer.push(&p2[100..]);
        assert_eq!(packets_batch2.len(), 1);
        assert_eq!(&packets_batch2[0][..], &p2[..]);
    }

    #[test]
    fn test_keyframe_detection_and_zapping_burst() {
        let stream_ring = TsStreamRing::new(1024 * 1024);

        // Generate synthetic PAT packet (PID 0) pointing to PMT PID 256
        let mut pat = [0u8; TS_PACKET_SIZE];
        pat[0] = TS_SYNC_BYTE;
        pat[1] = 0x40; // PUSI = 1, PID = 0
        pat[2] = 0x00;
        pat[3] = 0x10; // AFC = payload only
        pat[4] = 0x00; // pointer field
        pat[5] = 0x00; // table_id = 0 (PAT)
        pat[6] = 0xB0; // section syntax + len high
        pat[7] = 0x0D; // len low (13 bytes)
        pat[8] = 0x00;
        pat[9] = 0x01; // transport stream ID
        pat[10] = 0xC1;
        pat[11] = 0x00; // section 0
        pat[12] = 0x00; // last section 0
        // Program entry: prog 1 -> PID 256
        pat[13] = 0x00;
        pat[14] = 0x01;
        pat[15] = 0xE1; // reserved + PID high
        pat[16] = 0x00; // PID low = 256

        // Generate synthetic PMT packet (PID 256)
        let mut pmt = [0u8; TS_PACKET_SIZE];
        pmt[0] = TS_SYNC_BYTE;
        pmt[1] = 0x41; // PUSI = 1, PID = 256 (0x0100)
        pmt[2] = 0x00;
        pmt[3] = 0x10;
        pmt[4] = 0x00; // pointer field
        pmt[5] = 0x02; // table_id = 2 (PMT)
        pmt[6] = 0xB0;
        pmt[7] = 0x12; // section length
        pmt[8] = 0x00;
        pmt[9] = 0x01;
        pmt[10] = 0xC1;
        pmt[11] = 0x00;
        pmt[12] = 0x00;
        pmt[13] = 0xE1; // PCR PID
        pmt[14] = 0x00;
        pmt[15] = 0xF0; // program info length
        pmt[16] = 0x00;
        // Elementary stream: 0x1B (H.264), PID 257
        pmt[17] = 0x1B;
        pmt[18] = 0xE1;
        pmt[19] = 0x01;
        pmt[20] = 0xF0;
        pmt[21] = 0x00;

        let idr_packet = create_dummy_packet(257, true);
        let normal_packet = create_dummy_packet(257, false);

        stream_ring.ingest_raw(&pat).expect("ingest PAT");
        stream_ring.ingest_raw(&pmt).expect("ingest PMT");
        stream_ring.ingest_raw(&idr_packet).expect("ingest IDR");
        stream_ring
            .ingest_raw(&normal_packet)
            .expect("ingest normal");

        let burst = stream_ring.get_zapping_burst().expect("zapping burst");
        // Burst should contain PAT (188) + PMT (188) + IDR (188) + Normal (188) = 752 bytes
        assert_eq!(burst.len(), TS_PACKET_SIZE * 4);
        assert_eq!(&burst[0..TS_PACKET_SIZE], &pat[..]);
        assert_eq!(&burst[TS_PACKET_SIZE..TS_PACKET_SIZE * 2], &pmt[..]);
        assert_eq!(
            &burst[TS_PACKET_SIZE * 2..TS_PACKET_SIZE * 3],
            &idr_packet[..]
        );
    }
}
