#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]
#![allow(clippy::collapsible_if)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod arbiter;
pub mod config;
pub mod engine;
pub mod error;
pub mod ingest;
pub mod metrics;
pub mod moov;
pub mod range;
pub mod ring;
pub mod security;
pub mod signals;
pub mod storage;

pub use arbiter::{ArbiterGrant, ChannelArbiter, ConflictError, ConflictPolicy};
pub use config::{
    AirlockConfig, AirlockConfigFile, Args, CliArgs, ConfigError, ServerConfig, StorageConfig,
    StreamingConfig, expand_tilde, load_config_from_path, load_config_with_fallback, merge_args,
    merge_config_with_cli, resolve_config_path,
};
pub use engine::{
    AdaptiveJitterShield, CANDIDATE_ENDPOINTS, CatalogSyncManager, ChannelEntry, DiscoverConfig,
    HlsPlaylistGenerator, HlsSegment, HlsVariant, LineupManager, LineupStatus, MpegTsSynchronizer,
    TS_PACKET_SIZE, TS_SYNC_BYTE, TimeshiftConfig, TimeshiftRecorder, TimeshiftSegment,
    TsPacketMeta, TsRingSynchronizer, TsStreamRing, create_lineup_router,
    create_null_packets_chunk, create_ts_null_packet, extract_audio_pids_from_pmt,
    extract_pmt_pid_from_pat, extract_video_pid_from_pmt, parse_catalog_channels, parse_ts_packet,
};
pub use error::{
    AirlockError, IngestError, ProtocolError, SecurityError, StorageError, UpstreamError,
};
pub use ingest::{
    GuardedBroadcastStream, IngestState, LiveBroadcastHub, LiveBroadcastSession,
    LiveSubscriberGuard, StreamBufferSession, UpstreamHub, await_byte_offset,
};
pub use metrics::{render_metrics_response, render_prometheus_metrics};
pub use moov::{MoovProbeResult, fetch_tail_range, probe_mp4_boxes};
pub use range::{HttpRange, ResolvedByteRange, parse_range_header, resolve_range};
pub use ring::{LiveRingBuffer, RingChunk, RingStats};
pub use security::{
    RedactedString, RedactedUrl, SafeDnsResolver, SafePathGuard, hash_stream_id, redacted_string,
};
pub use signals::wait_for_shutdown_signal;
#[cfg(unix)]
pub use storage::posix_fadvise_dontneed_fd;
pub use storage::{
    AsyncBufferedChunkWriter, DEFAULT_BUFFER_CAPACITY, DiskUsageInfo, EvictionPolicy,
    HostMemoryInfo, MIN_MEMORY_HEADROOM_BYTES, QuotaConfig, QuotaManager, SegmentId, SegmentMeta,
    SharedQuotaManager, check_host_memory_headroom, posix_fadvise_dontneed, preallocate_file,
};
