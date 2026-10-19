//! Streaming media engine protocols, MPEG-TS ring synchronizer, adaptive slew rate controller,
//! and virtual HDHomeRun / M3U lineup emulation.

pub mod lineup;
pub mod slew;
pub mod ts_ring;

pub use lineup::{ChannelEntry, DiscoverConfig, LineupManager, LineupStatus, create_lineup_router};
pub use slew::{AdaptiveSlewController, SlewAction};
pub use ts_ring::{
    MpegTsSynchronizer, TS_PACKET_SIZE, TS_SYNC_BYTE, TsPacketMeta, TsStreamRing,
    extract_pmt_pid_from_pat, extract_video_pid_from_pmt, parse_ts_packet,
};
