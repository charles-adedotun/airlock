//! Virtual HDHomeRun and M3U playlist generation endpoints.
//!
//! Provides drop-in tuner emulation for Plex, Jellyfin, Emby, TiviMate, and Kodi,
//! enabling zero-friction local integration without custom client apps.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// An individual television channel entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelEntry {
    #[serde(rename = "GuideNumber")]
    pub guide_number: String,
    #[serde(rename = "GuideName")]
    pub guide_name: String,
    #[serde(rename = "URL")]
    pub stream_url: String,
    #[serde(rename = "HD")]
    pub hd: u8,
    #[serde(rename = "Favorite", default)]
    pub favorite: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tvg_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tvg_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tvg_logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_title: Option<String>,
}

/// HDHomeRun `/discover.json` descriptor schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverConfig {
    #[serde(rename = "FriendlyName")]
    pub friendly_name: String,
    #[serde(rename = "ModelNumber")]
    pub model_number: String,
    #[serde(rename = "FirmwareName")]
    pub firmware_name: String,
    #[serde(rename = "FirmwareVersion")]
    pub firmware_version: String,
    #[serde(rename = "DeviceID")]
    pub device_id: String,
    #[serde(rename = "DeviceAuth")]
    pub device_auth: String,
    #[serde(rename = "TunerCount")]
    pub tuner_count: usize,
    #[serde(rename = "BaseURL")]
    pub base_url: String,
    #[serde(rename = "LineupURL")]
    pub lineup_url: String,
}

/// HDHomeRun `/lineup_status.json` schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineupStatus {
    #[serde(rename = "ScanInProgress")]
    pub scan_in_progress: u8,
    #[serde(rename = "ScanPossible")]
    pub scan_possible: u8,
    #[serde(rename = "Source")]
    pub source: String,
    #[serde(rename = "SourceList")]
    pub source_list: Vec<String>,
}

/// Thread-safe manager for virtual HDHomeRun tuners and M3U playlists.
#[derive(Debug)]
pub struct LineupManager {
    base_url: String,
    device_id: String,
    friendly_name: String,
    tuner_count: usize,
    channels: RwLock<Vec<ChannelEntry>>,
}

impl LineupManager {
    /// Create a new LineupManager with the given base host URL and tuner parameters.
    pub fn new(base_url: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            device_id: device_id.into(),
            friendly_name: "Airlock Virtual Tuner".to_string(),
            tuner_count: 8,
            channels: RwLock::new(Vec::new()),
        }
    }

    /// Get the base host URL configured for this lineup manager.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Add a channel to the virtual lineup.
    pub fn add_channel(&self, channel: ChannelEntry) {
        if let Ok(mut lock) = self.channels.write() {
            lock.push(channel);
        }
    }

    /// Replace all channels in the virtual lineup.
    pub fn set_channels(&self, channels: Vec<ChannelEntry>) {
        if let Ok(mut lock) = self.channels.write() {
            *lock = channels;
        }
    }

    /// Get current lineup list for `/lineup.json`.
    pub fn get_lineup_json(&self) -> Vec<ChannelEntry> {
        self.channels.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// Generate HDHomeRun discover metadata.
    pub fn get_discover_json(&self) -> DiscoverConfig {
        DiscoverConfig {
            friendly_name: self.friendly_name.clone(),
            model_number: "HDHR-US".to_string(),
            firmware_name: "airlock_rust_v1".to_string(),
            firmware_version: "20261018".to_string(),
            device_id: self.device_id.clone(),
            device_auth: "airlock_auth_token".to_string(),
            tuner_count: self.tuner_count,
            base_url: self.base_url.clone(),
            lineup_url: format!("{}/lineup.json", self.base_url),
        }
    }

    /// Generate lineup scan status.
    pub fn get_lineup_status_json(&self) -> LineupStatus {
        LineupStatus {
            scan_in_progress: 0,
            scan_possible: 1,
            source: "Cable".to_string(),
            source_list: vec!["Cable".to_string()],
        }
    }

    /// Generate UPnP `device.xml` for auto-discovery by Plex/Emby/Jellyfin.
    pub fn generate_device_xml(&self) -> String {
        format!(
            r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <URLBase>{base_url}</URLBase>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
    <friendlyName>{friendly_name}</friendlyName>
    <manufacturer>Airlock Systems</manufacturer>
    <modelName>HDHR-US</modelName>
    <modelNumber>HDHR-US</modelNumber>
    <serialNumber>{device_id}</serialNumber>
    <UDN>uuid:20261018-0000-0000-0000-{device_id}</UDN>
  </device>
</root>"#,
            base_url = self.base_url,
            friendly_name = self.friendly_name,
            device_id = self.device_id,
        )
    }

    /// Generate standard IPTV `#EXTM3U` playlist for TiviMate, Apple TV, and Kodi.
    pub fn generate_m3u_playlist(&self) -> String {
        let channels = self.get_lineup_json();
        let mut m3u = String::with_capacity(channels.len() * 160 + 64);
        m3u.push_str("#EXTM3U\n");

        for ch in channels {
            let tvg_id = ch.tvg_id.as_deref().unwrap_or(&ch.guide_number);
            let tvg_name = ch.tvg_name.as_deref().unwrap_or(&ch.guide_name);
            let group = ch.group_title.as_deref().unwrap_or("Live TV");
            let logo = ch.tvg_logo.as_deref().unwrap_or("");

            m3u.push_str(&format!(
                r#"#EXTINF:-1 tvg-id="{tvg_id}" tvg-name="{tvg_name}" tvg-logo="{logo}" group-title="{group}",{name}"#,
                tvg_id = tvg_id,
                tvg_name = tvg_name,
                logo = logo,
                group = group,
                name = ch.guide_name
            ));
            m3u.push('\n');
            m3u.push_str(&ch.stream_url);
            m3u.push('\n');
        }

        m3u
    }
}

// Axum Route Handlers

async fn handle_discover(
    headers: HeaderMap,
    State(manager): State<Arc<LineupManager>>,
) -> Json<DiscoverConfig> {
    let mut config = manager.get_discover_json();
    if let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        if config.base_url.contains("://0.0.0.0:") {
            let schema = if config.base_url.starts_with("https://") { "https://" } else { "http://" };
            config.base_url = format!("{}{}", schema, host);
            config.lineup_url = format!("{}{}/lineup.json", schema, host);
        }
    }
    Json(config)
}

async fn handle_lineup_status(State(manager): State<Arc<LineupManager>>) -> Json<LineupStatus> {
    Json(manager.get_lineup_status_json())
}

async fn handle_lineup(
    headers: HeaderMap,
    State(manager): State<Arc<LineupManager>>,
) -> Json<Vec<ChannelEntry>> {
    let mut channels = manager.get_lineup_json();
    if let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        for ch in &mut channels {
            if ch.stream_url.contains("://0.0.0.0:") {
                let schema = if ch.stream_url.starts_with("https://") { "https://" } else { "http://" };
                let rest = &ch.stream_url[schema.len()..];
                if let Some(slash_idx) = rest.find('/') {
                    ch.stream_url = format!("{}{}{}", schema, host, &rest[slash_idx..]);
                }
            }
        }
    }
    Json(channels)
}

async fn handle_device_xml(
    headers: HeaderMap,
    State(manager): State<Arc<LineupManager>>,
) -> Response {
    let mut xml = manager.generate_device_xml();
    if let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        if xml.contains("://0.0.0.0:") {
            let schema = if xml.contains("https://0.0.0.0:") { "https://" } else { "http://" };
            if let Some(start) = xml.find(&format!("{}0.0.0.0:", schema)) {
                if let Some(end) = xml[start..].find("</URLBase>") {
                    let full_tag = &xml[start..start + end];
                    xml = xml.replace(full_tag, &format!("{}{}", schema, host));
                }
            }
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/xml"),
    );
    (StatusCode::OK, headers, xml).into_response()
}

async fn handle_playlist_m3u(
    headers: HeaderMap,
    State(manager): State<Arc<LineupManager>>,
) -> Response {
    let mut m3u = manager.generate_m3u_playlist();
    if let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        if m3u.contains("://0.0.0.0:") {
            let mut result = String::with_capacity(m3u.len());
            for line in m3u.lines() {
                if line.contains("://0.0.0.0:") {
                    let schema = if line.starts_with("https://") { "https://" } else { "http://" };
                    let rest = &line[schema.len()..];
                    if let Some(slash_idx) = rest.find('/') {
                        result.push_str(schema);
                        result.push_str(host);
                        result.push_str(&rest[slash_idx..]);
                        result.push('\n');
                        continue;
                    }
                }
                result.push_str(line);
                result.push('\n');
            }
            m3u = result;
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("audio/x-mpegurl; charset=utf-8"),
    );
    (StatusCode::OK, headers, m3u).into_response()
}

/// Create an Axum router serving HDHomeRun and M3U emulation endpoints.
pub fn create_lineup_router(manager: Arc<LineupManager>) -> Router {
    Router::new()
        .route("/discover.json", get(handle_discover))
        .route("/lineup_status.json", get(handle_lineup_status))
        .route("/lineup.json", get(handle_lineup))
        .route("/device.xml", get(handle_device_xml))
        .route("/playlist.m3u", get(handle_playlist_m3u))
        .route("/playlist.m3u8", get(handle_playlist_m3u))
        .with_state(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineup_json_and_m3u_generation() {
        let manager = LineupManager::new("http://192.168.1.100:8795", "104E9988");
        manager.add_channel(ChannelEntry {
            guide_number: "101".to_string(),
            guide_name: "Sky Sports Premier League HD".to_string(),
            stream_url: "http://192.168.1.100:8795/stream/live/101.ts".to_string(),
            hd: 1,
            favorite: 1,
            tvg_id: Some("sky.pl.hd".to_string()),
            tvg_name: Some("Sky Sports PL".to_string()),
            tvg_logo: Some("http://logo.com/sky.png".to_string()),
            group_title: Some("Sports".to_string()),
        });

        let lineup = manager.get_lineup_json();
        assert_eq!(lineup.len(), 1);
        assert_eq!(lineup[0].guide_number, "101");

        let discover = manager.get_discover_json();
        assert_eq!(discover.device_id, "104E9988");
        assert_eq!(discover.lineup_url, "http://192.168.1.100:8795/lineup.json");

        let m3u = manager.generate_m3u_playlist();
        assert!(m3u.starts_with("#EXTM3U"));
        assert!(m3u.contains(r#"group-title="Sports""#));
        assert!(m3u.contains("http://192.168.1.100:8795/stream/live/101.ts"));

        let xml = manager.generate_device_xml();
        assert!(xml.contains("<friendlyName>Airlock Virtual Tuner</friendlyName>"));
        assert!(xml.contains("104E9988"));
    }
}
