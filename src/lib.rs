#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod engine;
pub mod error;
pub mod ingest;
pub mod moov;
pub mod range;
pub mod ring;
pub mod security;
pub mod storage;

pub use engine::{
    AdaptiveSlewController, ChannelEntry, DiscoverConfig, LineupManager, LineupStatus,
    MpegTsSynchronizer, SlewAction, TS_PACKET_SIZE, TS_SYNC_BYTE, TsPacketMeta, TsStreamRing,
    extract_pmt_pid_from_pat, extract_video_pid_from_pmt, parse_ts_packet,
};
pub use error::{
    AirlockError, IngestError, ProtocolError, SecurityError, StorageError, UpstreamError,
};
pub use ingest::{IngestState, StreamBufferSession, UpstreamHub, await_byte_offset};
pub use moov::{MoovProbeResult, fetch_tail_range, probe_mp4_boxes};
pub use range::{HttpRange, ResolvedByteRange, parse_range_header, resolve_range};
pub use ring::{LiveRingBuffer, RingChunk, RingStats};
pub use security::{RedactedUrl, SafeDnsResolver, SafePathGuard, hash_stream_id};
pub use storage::{
    AsyncBufferedChunkWriter, DEFAULT_BUFFER_CAPACITY, DiskUsageInfo, EvictionPolicy,
    HostMemoryInfo, MIN_MEMORY_HEADROOM_BYTES, QuotaConfig, QuotaManager, SegmentId, SegmentMeta,
    SharedQuotaManager, check_host_memory_headroom, posix_fadvise_dontneed, preallocate_file,
};
