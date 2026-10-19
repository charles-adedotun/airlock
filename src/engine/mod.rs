//! Streaming media engine protocols, MPEG-TS ring synchronizer, adaptive slew rate controller,
//! rolling disk timeshift buffer, dynamic sliding-window HLS packaging, and virtual HDHomeRun lineup emulation.

pub mod catalog_sync;
pub mod hls;
pub mod lineup;
pub mod slew;
pub mod timeshift;
pub mod ts_ring;

pub use catalog_sync::{CANDIDATE_ENDPOINTS, CatalogSyncManager, parse_catalog_channels};
pub use hls::{HlsPlaylistGenerator, HlsSegment, HlsVariant};
pub use lineup::{ChannelEntry, DiscoverConfig, LineupManager, LineupStatus, create_lineup_router};
pub use slew::{AdaptiveSlewController, SlewAction};
pub use timeshift::{TimeshiftConfig, TimeshiftRecorder, TimeshiftSegment};
pub use ts_ring::{
    MpegTsSynchronizer, TS_PACKET_SIZE, TS_SYNC_BYTE, TsPacketMeta, TsStreamRing,
    extract_audio_pids_from_pmt, extract_pmt_pid_from_pat, extract_video_pid_from_pmt,
    parse_ts_packet,
};
