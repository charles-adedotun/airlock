//! Dynamic Sliding-Window RFC 8216 HLS Playlist Generator for live streams and timeshift buffers.
//!
//! Generates RFC 8216 compliant dynamic sliding-window HLS playlists (`index.m3u8`),
//! maintaining target durations, media sequence offsets, and segment metadata for
//! seamless playback in Apple Safari, iOS AVPlayer, and Chrome / Firefox via HLS.js.

use std::time::Duration;

use crate::engine::timeshift::{TimeshiftRecorder, TimeshiftSegment};
use crate::engine::ts_ring::TsStreamRing;
use crate::error::StorageError;

/// An individual HLS media segment descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct HlsSegment {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Exact segment playback duration.
    pub duration: Duration,
    /// Absolute or relative URI path where client can download the `.ts` chunk.
    pub uri: String,
    /// Optional human-readable segment title.
    pub title: Option<String>,
}

impl HlsSegment {
    /// Creates a new segment descriptor.
    pub fn new(sequence: u64, duration: Duration, uri: impl Into<String>) -> Self {
        Self {
            sequence,
            duration,
            uri: uri.into(),
            title: None,
        }
    }

    /// Sets the optional segment title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
}

/// A stream variant entry for RFC 8216 Master Playlists (`master.m3u8`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlsVariant {
    /// URI of the variant media playlist (`index.m3u8`).
    pub uri: String,
    /// Peak bitrate in bits per second.
    pub bandwidth: u64,
    /// Optional horizontal and vertical pixel resolution `(width, height)`.
    pub resolution: Option<(u32, u32)>,
    /// Optional RFC 6381 codec string (e.g. `"avc1.640028,mp4a.40.2"`).
    pub codecs: Option<String>,
    /// Optional descriptive name for the variant (e.g. `"1080p60"`).
    pub name: Option<String>,
}

/// Dynamic sliding-window HLS playlist generator.
#[derive(Debug, Clone)]
pub struct HlsPlaylistGenerator {
    /// Number of active segments to maintain in the sliding window (typically 5 to 10).
    pub window_size: usize,
    /// Explicit target duration tag value. If None, computed automatically from max segment duration.
    pub target_duration: Option<u64>,
    /// Optional URI prefix prepended to relative segment paths.
    pub uri_prefix: Option<String>,
}

impl Default for HlsPlaylistGenerator {
    fn default() -> Self {
        Self {
            window_size: 6,
            target_duration: None,
            uri_prefix: None,
        }
    }
}

impl HlsPlaylistGenerator {
    /// Creates a generator with the default sliding window size of 6 segments.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the sliding window size (clamped between 3 and 60 segments).
    pub fn with_window_size(mut self, window_size: usize) -> Self {
        self.window_size = window_size.clamp(3, 60);
        self
    }

    /// Overrides the target duration tag value.
    pub fn with_target_duration(mut self, target_duration: u64) -> Self {
        self.target_duration = Some(target_duration);
        self
    }

    /// Configures a base URI prefix prepended to all segment paths (e.g. `"/timeshift/live_123/"`).
    pub fn with_uri_prefix(mut self, prefix: impl Into<String>) -> Self {
        let mut p = prefix.into();
        if !p.is_empty() && !p.ends_with('/') {
            p.push('/');
        }
        self.uri_prefix = Some(p);
        self
    }

    /// Generates an RFC 8216 compliant dynamic sliding-window HLS playlist (`index.m3u8`)
    /// from an active `TimeshiftRecorder`.
    pub fn generate_from_timeshift(&self, recorder: &TimeshiftRecorder) -> String {
        let all_segments = recorder.segments();
        self.generate_from_timeshift_segments(&all_segments)
    }

    /// Generates an RFC 8216 sliding-window playlist from a slice of `TimeshiftSegment`s.
    pub fn generate_from_timeshift_segments(&self, all_segments: &[TimeshiftSegment]) -> String {
        if all_segments.is_empty() {
            let target = self.target_duration.unwrap_or(6);
            return format!(
                "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:{target}\n#EXT-X-MEDIA-SEQUENCE:0\n"
            );
        }

        let window_start = all_segments.len().saturating_sub(self.window_size);
        let window = &all_segments[window_start..];

        let converted: Vec<HlsSegment> = window
            .iter()
            .map(|seg| {
                let filename = format!("seg_{}.ts", seg.sequence);
                let uri = match &self.uri_prefix {
                    Some(prefix) => format!("{prefix}{filename}"),
                    None => filename,
                };
                HlsSegment {
                    sequence: seg.sequence,
                    duration: seg.duration,
                    uri,
                    title: None,
                }
            })
            .collect();

        self.generate_from_segments(&converted)
    }

    /// Generates an RFC 8216 sliding-window playlist from arbitrary `HlsSegment` entries.
    pub fn generate_from_segments(&self, segments: &[HlsSegment]) -> String {
        let target_duration = if let Some(td) = self.target_duration {
            td
        } else if segments.is_empty() {
            6
        } else {
            let max_sec = segments
                .iter()
                .map(|s| s.duration.as_secs_f64())
                .fold(6.0_f64, f64::max);
            max_sec.ceil() as u64
        };

        let media_sequence = segments.first().map(|s| s.sequence).unwrap_or(0);

        let mut out = String::with_capacity(512);
        out.push_str("#EXTM3U\n");
        out.push_str("#EXT-X-VERSION:3\n");
        out.push_str(&format!("#EXT-X-TARGETDURATION:{target_duration}\n"));
        out.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{media_sequence}\n"));

        for seg in segments {
            let title = seg.title.as_deref().unwrap_or("");
            out.push_str(&format!(
                "#EXTINF:{:.6},{title}\n",
                seg.duration.as_secs_f64()
            ));
            out.push_str(&seg.uri);
            out.push('\n');
        }

        // Live dynamic sliding-window playlists MUST NOT contain #EXT-X-ENDLIST
        out
    }

    /// Generates an RFC 8216 sliding-window playlist dynamically from active keyframe boundaries
    /// in a `TsStreamRing` in-memory buffer.
    pub fn generate_from_ts_ring(
        &self,
        ring: &TsStreamRing,
        base_uri: &str,
    ) -> Result<String, StorageError> {
        // Read chunks from the beginning of available ring
        let (chunks, _) = ring.read_from(0, 10_000)?;
        if chunks.is_empty() {
            return Ok(self.generate_from_segments(&[]));
        }

        // Identify keyframe boundaries
        let mut keyframe_indices = Vec::new();
        for chunk in &chunks {
            if chunk.is_keyframe {
                keyframe_indices.push(chunk.sequence);
            }
        }

        // If no keyframes found, treat the current head as a single virtual segment
        if keyframe_indices.is_empty() {
            if let Some(first) = chunks.first() {
                keyframe_indices.push(first.sequence);
            }
        }

        let prefix = base_uri.trim_end_matches('/');
        let window_start = keyframe_indices.len().saturating_sub(self.window_size);
        let active_keyframes = &keyframe_indices[window_start..];

        let mut segments = Vec::with_capacity(active_keyframes.len());
        for (i, &key_seq) in active_keyframes.iter().enumerate() {
            let seg_seq = window_start + i;
            let uri = format!("{prefix}/ring_seg_{key_seq}.ts");
            let duration = Duration::from_secs(self.target_duration.unwrap_or(6));
            segments.push(HlsSegment::new(seg_seq as u64, duration, uri));
        }

        Ok(self.generate_from_segments(&segments))
    }

    /// Generates an RFC 8216 multivariant master playlist (`master.m3u8`).
    pub fn generate_master_playlist(variants: &[HlsVariant]) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("#EXTM3U\n");
        out.push_str("#EXT-X-VERSION:3\n");

        for var in variants {
            let mut inf = format!("#EXT-X-STREAM-INF:BANDWIDTH={}", var.bandwidth);
            if let Some((w, h)) = var.resolution {
                inf.push_str(&format!(",RESOLUTION={w}x{h}"));
            }
            if let Some(ref codecs) = var.codecs {
                inf.push_str(&format!(",CODECS=\"{codecs}\""));
            }
            if let Some(ref name) = var.name {
                inf.push_str(&format!(",NAME=\"{name}\""));
            }
            out.push_str(&inf);
            out.push('\n');
            out.push_str(&var.uri);
            out.push('\n');
        }

        out
    }
}
