use crate::error::{AirlockError, ProtocolError};
use bytes::Bytes;

/// Result of scanning an MP4 container's header window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoovProbeResult {
    /// `moov` atom is present at the beginning of the file (faststart enabled).
    FastStart {
        moov_offset: usize,
        moov_size: usize,
    },
    /// `mdat` (media data) was encountered before `moov`. Metadata is at the tail of the file!
    MoovAtEnd { mdat_offset: usize },
    /// Header was incomplete or did not contain recognizable MP4 boxes.
    Unrecognized,
}

/// Scan initial bytes of a media stream to identify MP4 atom layout.
pub fn probe_mp4_boxes(data: &[u8]) -> MoovProbeResult {
    let mut offset = 0;
    let mut found_mdat = false;
    let mut mdat_offset = 0;

    while offset + 8 <= data.len() {
        let size_bytes: [u8; 4] = match data[offset..offset + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        };
        let box_size = u32::from_be_bytes(size_bytes) as usize;
        let box_type = &data[offset + 4..offset + 8];

        if box_type == b"moov" {
            if found_mdat {
                // moov appeared after mdat
                return MoovProbeResult::MoovAtEnd { mdat_offset };
            }
            return MoovProbeResult::FastStart {
                moov_offset: offset,
                moov_size: if box_size == 1 && offset + 16 <= data.len() {
                    // 64-bit extended box size
                    let ext_bytes: [u8; 8] =
                        data[offset + 8..offset + 16].try_into().unwrap_or([0; 8]);
                    u64::from_be_bytes(ext_bytes) as usize
                } else {
                    box_size
                },
            };
        } else if box_type == b"mdat" {
            found_mdat = true;
            mdat_offset = offset;
        }

        // Advance to next box
        let advance = if box_size == 0 {
            // Box extends to end of file
            data.len() - offset
        } else if box_size == 1 && offset + 16 <= data.len() {
            // 64-bit extended size
            let ext_bytes: [u8; 8] = data[offset + 8..offset + 16].try_into().unwrap_or([0; 8]);
            u64::from_be_bytes(ext_bytes) as usize
        } else {
            box_size
        };

        if advance < 8 {
            break; // Corrupted or truncated box
        }
        offset += advance;
    }

    if found_mdat {
        MoovProbeResult::MoovAtEnd { mdat_offset }
    } else {
        MoovProbeResult::Unrecognized
    }
}

/// Suffix Range probe helper for non-faststart MP4 files.
/// Issues an out-of-band HTTP Range request to fetch the tail (default 2MB) of the file.
pub async fn fetch_tail_range(
    client: &reqwest::Client,
    upstream_url: &str,
    tail_bytes: u64,
) -> Result<Bytes, AirlockError> {
    let range_header = format!("bytes=-{tail_bytes}");
    let response = client
        .get(upstream_url)
        .header("Range", range_header)
        .send()
        .await
        .map_err(|e| AirlockError::Ingest(crate::error::IngestError::Network(e)))?;

    if !response.status().is_success() && response.status() != reqwest::StatusCode::PARTIAL_CONTENT
    {
        return Err(AirlockError::Protocol(ProtocolError::InvalidRange(
            format!(
                "Upstream rejected suffix range with status: {}",
                response.status()
            ),
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AirlockError::Ingest(crate::error::IngestError::Network(e)))?;
    Ok(bytes)
}
