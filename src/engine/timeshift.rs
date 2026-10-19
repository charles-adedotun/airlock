//! Rolling Disk Timeshift Buffer for live MPEG-TS streams.
//!
//! Provides ring-buffered on-disk persistence (`timeshift/<stream_id>/seg_<seq>.ts`),
//! keyframe-aligned segment slicing, automatic kernel page cache dropping (`posix_fadvise_dontneed_fd`),
//! rolling window time/quota eviction, and timestamp/sequence seeking.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::engine::ts_ring::{MpegTsSynchronizer, parse_ts_packet};
use crate::error::StorageError;

/// Configuration for the rolling disk timeshift recorder.
#[derive(Debug, Clone)]
pub struct TimeshiftConfig {
    /// Base storage directory. Segments are written to `{base_dir}/timeshift/{stream_id}/seg_{seq}.ts`.
    pub base_dir: PathBuf,
    /// Identifier for the live stream.
    pub stream_id: String,
    /// Target duration for each segment. Segments slice on keyframes once this duration is reached.
    pub segment_duration: Duration,
    /// Hard upper bound on segment duration before forcing a slice without a keyframe.
    pub max_segment_duration: Duration,
    /// Maximum timeshift retention window (e.g. 2 hours). Segments older than this are unlinked.
    pub max_timeshift_duration: Duration,
    /// Maximum disk quota in bytes for this timeshift stream. If exceeded, oldest segments are unlinked.
    pub max_disk_bytes: Option<u64>,
    /// Optional upper limit on the total number of retained segments.
    pub max_segments: Option<usize>,
}

impl TimeshiftConfig {
    /// Creates a new configuration with standard broadcast defaults:
    /// - 6-second target segment duration
    /// - 12-second maximum segment duration
    /// - 2-hour retention window
    pub fn new(base_dir: impl Into<PathBuf>, stream_id: impl Into<String>) -> Self {
        Self {
            base_dir: base_dir.into(),
            stream_id: stream_id.into(),
            segment_duration: Duration::from_secs(6),
            max_segment_duration: Duration::from_secs(12),
            max_timeshift_duration: Duration::from_secs(7200), // 2 hours
            max_disk_bytes: None,
            max_segments: None,
        }
    }

    /// Sets the target segment duration.
    pub fn with_segment_duration(mut self, duration: Duration) -> Self {
        self.segment_duration = duration;
        if self.max_segment_duration < duration {
            self.max_segment_duration = duration * 2;
        }
        self
    }

    /// Sets the maximum segment duration before forcing a slice.
    pub fn with_max_segment_duration(mut self, max: Duration) -> Self {
        self.max_segment_duration = max;
        self
    }

    /// Sets the maximum timeshift retention window duration.
    pub fn with_max_timeshift_duration(mut self, duration: Duration) -> Self {
        self.max_timeshift_duration = duration;
        self
    }

    /// Sets the maximum disk quota in bytes for this stream.
    pub fn with_max_disk_bytes(mut self, bytes: u64) -> Self {
        self.max_disk_bytes = Some(bytes);
        self
    }

    /// Sets the maximum number of historical segments retained in the rolling buffer.
    pub fn with_max_segments(mut self, max: usize) -> Self {
        self.max_segments = Some(max);
        self
    }
}

/// Metadata describing a finalized timeshift media segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeshiftSegment {
    /// Monotonically increasing segment sequence number (0, 1, 2, ...).
    pub sequence: u64,
    /// Absolute or relative path to the chunk file on disk.
    pub file_path: PathBuf,
    /// Byte size of the segment file.
    pub byte_length: u64,
    /// Playback duration of the segment.
    pub duration: Duration,
    /// Wall-clock timestamp when this segment began recording.
    pub start_timestamp: SystemTime,
}

impl TimeshiftSegment {
    /// Playback duration in fractional seconds for RFC 8216 EXTINF formatting.
    pub fn duration_secs(&self) -> f64 {
        self.duration.as_secs_f64()
    }
}

/// State tracking for the currently open, active recording segment.
struct ActiveSegment {
    sequence: u64,
    file: tokio::fs::File,
    file_path: PathBuf,
    bytes_written: u64,
    start_time: Instant,
    start_timestamp: SystemTime,
}

/// In-memory rolling index of completed timeshift segments.
#[derive(Debug, Default)]
struct TimeshiftIndex {
    segments: VecDeque<TimeshiftSegment>,
    total_disk_bytes: u64,
    total_duration: Duration,
}

/// High-throughput Rolling Disk Timeshift Recorder for live MPEG-TS streams.
pub struct TimeshiftRecorder {
    config: TimeshiftConfig,
    stream_dir: PathBuf,
    active: tokio::sync::Mutex<Option<ActiveSegment>>,
    next_sequence: AtomicU64,
    index: RwLock<TimeshiftIndex>,
    fadvise_drop_count: AtomicU64,
    sync_mutex: std::sync::Mutex<MpegTsSynchronizer>,
}

impl TimeshiftRecorder {
    /// Creates a new `TimeshiftRecorder` for the specified configuration.
    /// Ensures `{base_dir}/timeshift/{stream_id}` exists on disk.
    pub fn new(config: TimeshiftConfig) -> Result<Self, StorageError> {
        let stream_dir = config.base_dir.join("timeshift").join(&config.stream_id);

        std::fs::create_dir_all(&stream_dir).map_err(StorageError::Io)?;

        Ok(Self {
            config,
            stream_dir,
            active: tokio::sync::Mutex::new(None),
            next_sequence: AtomicU64::new(0),
            index: RwLock::new(TimeshiftIndex::default()),
            fadvise_drop_count: AtomicU64::new(0),
            sync_mutex: std::sync::Mutex::new(MpegTsSynchronizer::new()),
        })
    }

    /// Convenience constructor with target segment duration.
    pub fn with_segment_duration(
        base_dir: impl Into<PathBuf>,
        stream_id: impl Into<String>,
        segment_duration: Duration,
    ) -> Result<Self, StorageError> {
        let config =
            TimeshiftConfig::new(base_dir, stream_id).with_segment_duration(segment_duration);
        Self::new(config)
    }

    /// Accessor for configuration.
    pub fn config(&self) -> &TimeshiftConfig {
        &self.config
    }

    /// Directory storing segment files on disk.
    pub fn stream_dir(&self) -> &Path {
        &self.stream_dir
    }

    /// Number of kernel page cache drops performed via `posix_fadvise_dontneed_fd`.
    pub fn fadvise_drop_count(&self) -> u64 {
        self.fadvise_drop_count.load(Ordering::SeqCst)
    }

    /// Total number of indexed, completed segments available for timeshift playback.
    pub fn segment_count(&self) -> usize {
        self.index.read().map(|idx| idx.segments.len()).unwrap_or(0)
    }

    /// Total disk bytes consumed by finalized segments.
    pub fn total_disk_bytes(&self) -> u64 {
        self.index
            .read()
            .map(|idx| idx.total_disk_bytes)
            .unwrap_or(0)
    }

    /// Total duration of all currently indexed segments.
    pub fn total_duration(&self) -> Duration {
        self.index
            .read()
            .map(|idx| idx.total_duration)
            .unwrap_or_default()
    }

    /// Retrieve a snapshot of all active, indexed segments in ascending sequence order.
    pub fn segments(&self) -> Vec<TimeshiftSegment> {
        self.index
            .read()
            .map(|idx| idx.segments.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Seek and locate a segment by its exact sequence number.
    pub fn seek_by_sequence(&self, sequence: u64) -> Option<TimeshiftSegment> {
        self.index
            .read()
            .ok()?
            .segments
            .iter()
            .find(|seg| seg.sequence == sequence)
            .cloned()
    }

    /// Seek and locate a segment containing the specified wall-clock timestamp.
    pub fn seek_by_timestamp(&self, timestamp: SystemTime) -> Option<TimeshiftSegment> {
        let idx = self.index.read().ok()?;
        if idx.segments.is_empty() {
            return None;
        }

        // Search for segment spanning [start_timestamp, start_timestamp + duration)
        for seg in &idx.segments {
            let end_timestamp = seg.start_timestamp + seg.duration;
            if timestamp >= seg.start_timestamp && timestamp < end_timestamp {
                return Some(seg.clone());
            }
        }

        // If timestamp is at or beyond the latest segment's start, return the latest segment
        if let Some(last) = idx.segments.back() {
            if timestamp >= last.start_timestamp {
                return Some(last.clone());
            }
        }

        None
    }

    /// Seek the closest segment to a given timestamp, even if strictly outside bounds.
    pub fn seek_closest_by_timestamp(&self, timestamp: SystemTime) -> Option<TimeshiftSegment> {
        let idx = self.index.read().ok()?;
        if idx.segments.is_empty() {
            return None;
        }

        let mut closest: Option<TimeshiftSegment> = None;
        let mut min_diff: Option<Duration> = None;

        for seg in &idx.segments {
            let diff = if timestamp >= seg.start_timestamp {
                timestamp
                    .duration_since(seg.start_timestamp)
                    .unwrap_or_default()
            } else {
                seg.start_timestamp
                    .duration_since(timestamp)
                    .unwrap_or_default()
            };

            match min_diff {
                None => {
                    min_diff = Some(diff);
                    closest = Some(seg.clone());
                }
                Some(d) if diff < d => {
                    min_diff = Some(diff);
                    closest = Some(seg.clone());
                }
                _ => {}
            }
        }

        closest
    }

    /// Reads the raw MPEG-TS byte content of a historical segment from disk.
    pub async fn read_segment_bytes(&self, sequence: u64) -> Result<Bytes, StorageError> {
        let seg = self.seek_by_sequence(sequence).ok_or_else(|| {
            StorageError::FileNotFound(format!(
                "Timeshift segment {sequence} for stream '{}' not found",
                self.config.stream_id
            ))
        })?;

        let data = tokio::fs::read(&seg.file_path)
            .await
            .map_err(StorageError::Io)?;

        Ok(Bytes::from(data))
    }

    /// Opens an existing segment file for zero-copy downstream range streaming.
    pub async fn open_segment_file(&self, sequence: u64) -> Result<tokio::fs::File, StorageError> {
        let seg = self.seek_by_sequence(sequence).ok_or_else(|| {
            StorageError::FileNotFound(format!(
                "Timeshift segment {sequence} for stream '{}' not found",
                self.config.stream_id
            ))
        })?;

        tokio::fs::File::open(&seg.file_path)
            .await
            .map_err(StorageError::Io)
    }

    /// Ingests a pre-parsed 188-byte MPEG-TS packet with explicit keyframe boundary indicator.
    pub async fn ingest_packet(
        &self,
        packet: &[u8],
        is_keyframe: bool,
    ) -> Result<(), StorageError> {
        if packet.is_empty() {
            return Ok(());
        }

        let mut active_lock = self.active.lock().await;

        let should_slice = match *active_lock {
            Some(ref act) if act.bytes_written > 0 => {
                let elapsed = act.start_time.elapsed();
                (is_keyframe && elapsed >= self.config.segment_duration)
                    || elapsed >= self.config.max_segment_duration
            }
            _ => false,
        };

        if should_slice {
            let completed = self.close_active_segment(&mut active_lock).await?;
            if let Some(seg) = completed {
                self.record_segment_and_evict(seg).await?;
            }
        }

        // Ensure active segment is open
        if active_lock.is_none() {
            let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
            let file_path = self.stream_dir.join(format!("seg_{seq}.ts"));
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_path)
                .await
                .map_err(StorageError::Io)?;

            *active_lock = Some(ActiveSegment {
                sequence: seq,
                file,
                file_path,
                bytes_written: 0,
                start_time: Instant::now(),
                start_timestamp: SystemTime::now(),
            });
        }

        if let Some(ref mut act) = *active_lock {
            act.file.write_all(packet).await.map_err(StorageError::Io)?;
            act.bytes_written += packet.len() as u64;
        }

        Ok(())
    }

    /// Ingests raw MPEG-TS byte chunks, resynchronizing on 188-byte sync bytes (0x47)
    /// and detecting IDR keyframes automatically.
    pub async fn ingest_raw(&self, data: &[u8]) -> Result<usize, StorageError> {
        let packets = {
            let mut sync = self.sync_mutex.lock().map_err(|_| {
                StorageError::Io(std::io::Error::other("MpegTsSynchronizer mutex poisoned"))
            })?;
            sync.push(data)
        };

        let count = packets.len();
        for packet in packets {
            let is_idr = parse_ts_packet(&packet, None, None)
                .map(|m| m.is_idr)
                .unwrap_or(false);

            self.ingest_packet(&packet, is_idr).await?;
        }

        Ok(count)
    }

    /// Forcefully rolls the current active segment into the completed index.
    pub async fn force_rotate(&self) -> Result<Option<TimeshiftSegment>, StorageError> {
        let mut active_lock = self.active.lock().await;
        let completed = self.close_active_segment(&mut active_lock).await?;
        if let Some(ref seg) = completed {
            self.record_segment_and_evict(seg.clone()).await?;
        }
        Ok(completed)
    }

    /// Flushes all pending writes for the active segment to disk.
    pub async fn flush(&self) -> Result<(), StorageError> {
        let mut active_lock = self.active.lock().await;
        if let Some(ref mut act) = *active_lock {
            act.file.flush().await.map_err(StorageError::Io)?;
        }
        Ok(())
    }

    /// Closes the active segment, calls `posix_fadvise_dontneed_fd` on segment completion,
    /// and returns the completed segment metadata.
    async fn close_active_segment(
        &self,
        active_opt: &mut Option<ActiveSegment>,
    ) -> Result<Option<TimeshiftSegment>, StorageError> {
        let mut active = match active_opt.take() {
            Some(act) => act,
            None => return Ok(None),
        };

        if active.bytes_written == 0 {
            // Drop empty file and remove it
            drop(active.file);
            let _ = tokio::fs::remove_file(&active.file_path).await;
            return Ok(None);
        }

        active.file.flush().await.map_err(StorageError::Io)?;

        // Drop pages from OS page cache using raw FD on segment completion
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = active.file.as_raw_fd();
            let _ = crate::storage::posix_fadvise_dontneed_fd(fd, 0, active.bytes_written as i64);
        }
        self.fadvise_drop_count.fetch_add(1, Ordering::SeqCst);

        drop(active.file);

        let now = SystemTime::now();
        let elapsed = now
            .duration_since(active.start_timestamp)
            .unwrap_or_else(|_| active.start_time.elapsed());
        let duration = if elapsed.is_zero() {
            self.config.segment_duration
        } else {
            elapsed
        };

        let segment = TimeshiftSegment {
            sequence: active.sequence,
            file_path: active.file_path,
            byte_length: active.bytes_written,
            duration,
            start_timestamp: active.start_timestamp,
        };

        Ok(Some(segment))
    }

    /// Adds the completed segment to the index and evicts segments exceeding retention/quota.
    async fn record_segment_and_evict(
        &self,
        segment: TimeshiftSegment,
    ) -> Result<(), StorageError> {
        let mut to_unlink: Vec<PathBuf> = Vec::new();

        {
            let mut idx = self.index.write().map_err(|_| {
                StorageError::Io(std::io::Error::other("TimeshiftIndex RwLock poisoned"))
            })?;

            idx.total_disk_bytes += segment.byte_length;
            idx.total_duration += segment.duration;
            idx.segments.push_back(segment);

            let now = SystemTime::now();

            // Enforce rolling timeshift window, disk quota, and segment count limits
            while idx.segments.len() > 1 {
                let oldest = match idx.segments.front() {
                    Some(s) => s,
                    None => break,
                };

                let age_exceeded = if let Ok(age) = now.duration_since(oldest.start_timestamp) {
                    age > self.config.max_timeshift_duration
                } else {
                    false
                };

                let duration_window_exceeded =
                    idx.total_duration > self.config.max_timeshift_duration;

                let disk_quota_exceeded = match self.config.max_disk_bytes {
                    Some(max_bytes) => idx.total_disk_bytes > max_bytes,
                    None => false,
                };

                let max_segments_exceeded = match self.config.max_segments {
                    Some(max_count) => idx.segments.len() > max_count,
                    None => false,
                };

                if age_exceeded
                    || duration_window_exceeded
                    || disk_quota_exceeded
                    || max_segments_exceeded
                {
                    if let Some(removed) = idx.segments.pop_front() {
                        idx.total_disk_bytes =
                            idx.total_disk_bytes.saturating_sub(removed.byte_length);
                        idx.total_duration = idx.total_duration.saturating_sub(removed.duration);
                        to_unlink.push(removed.file_path);
                    }
                } else {
                    break;
                }
            }
        }

        // Unlink expired segment chunk files from disk
        for path in to_unlink {
            let _ = tokio::fs::remove_file(&path).await;
            tracing::debug!(path = %path.display(), "Unlinked evicted timeshift segment");
        }

        Ok(())
    }
}
