//! Automated Live Channel Lineup & EPG Catalog Sync for virtual TV tuners.
//!
//! Synchronizes channel lineups from upstream Python catalog backends (`:8794`),
//! Xtream Codes APIs (`/player_api.php?action=get_live_streams`), and curated
//! entertainment hubs (`/api/entertainment/channels`, `/api/entertainment/hub`).
//! Formats stream playback URLs to point locally to the Airlock proxy arbiter,
//! ensuring single-upstream socket protection and circular TS jitter-shield buffering.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::engine::lineup::{ChannelEntry, LineupManager};
use crate::error::{AirlockError, IngestError};
use crate::security::RedactedUrl;

/// Default candidate endpoints checked when syncing from a catalog base URL.
pub const CANDIDATE_ENDPOINTS: &[&str] = &[
    "/api/entertainment/hub",
    "/api/entertainment/channels",
    "/player_api.php?action=get_live_streams",
];

/// Automated catalog and EPG synchronization manager for virtual TV tuners.
#[derive(Debug)]
pub struct CatalogSyncManager {
    lineup_manager: Arc<LineupManager>,
    client: reqwest::Client,
    catalog_url: String,
    stream_base_url: Option<String>,
    endpoint_path: Option<String>,
}

impl CatalogSyncManager {
    /// Creates a new `CatalogSyncManager` bound to the given lineup manager, HTTP client,
    /// and catalog service base URL.
    pub fn new(
        lineup_manager: Arc<LineupManager>,
        client: reqwest::Client,
        catalog_url: impl Into<String>,
    ) -> Self {
        Self {
            lineup_manager,
            client,
            catalog_url: catalog_url.into(),
            stream_base_url: None,
            endpoint_path: None,
        }
    }

    /// Sets an explicit stream base URL override for generated `stream_url` entries.
    /// If not set, defaults to `LineupManager::base_url()`.
    pub fn with_stream_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.stream_base_url = Some(base_url.into());
        self
    }

    /// Sets an explicit endpoint path (e.g. `"/api/entertainment/channels"`).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_path = Some(endpoint.into());
        self
    }

    /// Returns the configured catalog base URL.
    pub fn catalog_url(&self) -> &str {
        &self.catalog_url
    }

    /// Returns a reference to the inner `LineupManager`.
    pub fn lineup_manager(&self) -> &Arc<LineupManager> {
        &self.lineup_manager
    }

    /// Fetches live channels from the catalog service, parses them into `ChannelEntry` structs,
    /// populates the inner `LineupManager`, and returns the total count of synced channels.
    pub async fn sync_from_catalog(&self) -> Result<usize, AirlockError> {
        let base = self.catalog_url.trim_end_matches('/');

        // If an explicit endpoint was configured, fetch it directly
        if let Some(ref ep) = self.endpoint_path {
            let ep_norm = if ep.starts_with('/') {
                ep.clone()
            } else {
                format!("/{ep}")
            };
            let target_url = format!("{base}{ep_norm}");
            return self.sync_from_url(&target_url).await;
        }

        // If catalog_url already contained a specific path, fetch it directly
        if let Ok(parsed) = url::Url::parse(&self.catalog_url) {
            let path = parsed.path();
            if !path.is_empty() && path != "/" {
                return self.sync_from_url(&self.catalog_url).await;
            }
        }

        // Otherwise iterate candidate endpoints in order:
        // /api/entertainment/channels -> /api/entertainment/hub -> /player_api.php?action=get_live_streams
        let mut last_err = None;
        for endpoint in CANDIDATE_ENDPOINTS {
            let target_url = format!("{base}{endpoint}");
            debug!(target = %RedactedUrl::sanitize_str(&target_url), "Probing catalog endpoint");

            match self.client.get(&target_url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let bytes = resp
                            .bytes()
                            .await
                            .map_err(|e| AirlockError::Ingest(IngestError::Network(e)))?;
                        let json_val: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(|e| {
                                AirlockError::Internal(format!(
                                    "Failed to parse catalog JSON from {}: {e}",
                                    RedactedUrl::sanitize_str(&target_url)
                                ))
                            })?;
                        // If endpoint returned an error object (e.g. {"error": "not found"} with HTTP 200), try next candidate
                        if json_val.get("error").is_some()
                            && json_val.get("curated_live_tv").is_none()
                            && json_val.get("items").is_none()
                            && json_val.get("channels").is_none()
                        {
                            debug!(target = %RedactedUrl::sanitize_str(&target_url), "Endpoint returned JSON error payload, trying next candidate");
                            continue;
                        }

                        let res = self.apply_catalog_json(&json_val)?;
                        if res > 0 {
                            return Ok(res);
                        }
                    } else if status == reqwest::StatusCode::NOT_FOUND
                        || status == reqwest::StatusCode::BAD_REQUEST
                    {
                        debug!(
                            status = %status,
                            endpoint = %endpoint,
                            "Candidate endpoint not supported by catalog, trying next candidate"
                        );
                        last_err = Some(AirlockError::Ingest(IngestError::BadStatus(status)));
                    } else {
                        warn!(
                            status = %status,
                            target = %RedactedUrl::sanitize_str(&target_url),
                            "Catalog endpoint returned HTTP error status"
                        );
                        return Err(AirlockError::Ingest(IngestError::BadStatus(status)));
                    }
                }
                Err(err) => {
                    warn!(error = %err, target = %RedactedUrl::sanitize_str(&target_url), "Network connection to catalog failed");
                    return Err(AirlockError::Ingest(IngestError::Network(err)));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AirlockError::Ingest(IngestError::BadStatus(reqwest::StatusCode::NOT_FOUND))
        }))
    }

    /// Fetches channel metadata from an explicit target URL and populates the lineup.
    pub async fn sync_from_url(&self, target_url: &str) -> Result<usize, AirlockError> {
        let resp = self
            .client
            .get(target_url)
            .send()
            .await
            .map_err(|e| AirlockError::Ingest(IngestError::Network(e)))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(AirlockError::Ingest(IngestError::BadStatus(status)));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AirlockError::Ingest(IngestError::Network(e)))?;

        let json_val: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            AirlockError::Internal(format!(
                "Failed to parse catalog JSON from {}: {e}",
                RedactedUrl::sanitize_str(target_url)
            ))
        })?;

        self.apply_catalog_json(&json_val)
    }

    /// Parses catalog JSON and applies the resulting channels to `LineupManager`.
    fn apply_catalog_json(&self, json_val: &serde_json::Value) -> Result<usize, AirlockError> {
        let effective_base_url = self
            .stream_base_url
            .as_deref()
            .unwrap_or_else(|| self.lineup_manager.base_url());

        let channels = parse_catalog_channels(json_val, effective_base_url);
        let count = channels.len();
        self.lineup_manager.set_channels(channels);
        info!(
            count = count,
            "Successfully synchronized channels from catalog"
        );
        Ok(count)
    }

    /// Spawns a Tokio background task that executes an immediate sync on startup,
    /// and then repeats every `interval` until a shutdown signal is received.
    pub fn spawn_periodic_sync(
        self: Arc<Self>,
        interval: Duration,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                interval_secs = interval.as_secs(),
                "Catalog sync background worker started"
            );

            // Check if already in shutdown state
            if *shutdown_rx.borrow() {
                debug!("Catalog sync received shutdown before initial sync, exiting");
                return;
            }

            // Immediate initial sync on startup
            if let Err(err) = self.sync_from_catalog().await {
                warn!(error = %err, "Initial catalog synchronization failed");
            }

            let mut timer = tokio::time::interval(interval);
            // interval() ticks immediately; consume initial tick since we just executed initial sync
            timer.tick().await;

            loop {
                tokio::select! {
                    biased;
                    change = shutdown_rx.changed() => {
                        match change {
                            Ok(()) => {
                                if *shutdown_rx.borrow() {
                                    info!("Catalog sync worker received shutdown signal, shutting down");
                                    break;
                                }
                            }
                            Err(_) => {
                                info!("Catalog sync shutdown channel dropped, worker terminating");
                                break;
                            }
                        }
                    }
                    _ = timer.tick() => {
                        debug!("Periodic catalog sync interval elapsed, initiating sync");
                        if let Err(err) = self.sync_from_catalog().await {
                            warn!(error = %err, "Periodic catalog sync iteration failed");
                        }
                    }
                }
            }

            info!("Catalog sync background worker stopped");
        })
    }
}

/// Helper capitalizing the first character of a genre or category name.
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Extracts a string-based stream ID from a JSON channel object.
fn extract_stream_id(obj: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for key in &["stream_id", "streamId", "id", "channel_id"] {
        if let Some(val) = obj.get(*key) {
            if let Some(s) = val.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            } else if let Some(n) = val.as_i64() {
                if n > 0 {
                    return Some(n.to_string());
                }
            } else if let Some(n) = val.as_u64() {
                if n > 0 {
                    return Some(n.to_string());
                }
            }
        }
    }

    // Fallback: extract identifier from existing proxy URL if present
    if let Some(url_str) = obj
        .get("URL")
        .or_else(|| obj.get("stream_url"))
        .and_then(|v| v.as_str())
    {
        if let Some(last_seg) = url_str.split('/').next_back() {
            let clean = last_seg
                .strip_suffix(".ts")
                .or_else(|| last_seg.strip_suffix(".m3u8"))
                .unwrap_or(last_seg);
            if !clean.is_empty()
                && clean
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Some(clean.to_string());
            }
        }
    }

    None
}

/// Extracts the guide channel number, falling back to sequential 1-based index.
fn extract_guide_number(obj: &serde_json::Map<String, serde_json::Value>, index: usize) -> String {
    for key in &[
        "GuideNumber",
        "guide_number",
        "guideNumber",
        "num",
        "channel_number",
        "channel_num",
        "ch_num",
    ] {
        if let Some(val) = obj.get(*key) {
            if let Some(s) = val.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() && trimmed != "0" {
                    return trimmed.to_string();
                }
            } else if let Some(n) = val.as_i64() {
                if n > 0 {
                    return n.to_string();
                }
            } else if let Some(n) = val.as_u64() {
                if n > 0 {
                    return n.to_string();
                }
            }
        }
    }
    (index + 1).to_string()
}

/// Extracts the human-readable channel name or title.
fn extract_guide_name(
    obj: &serde_json::Map<String, serde_json::Value>,
    fallback_num: &str,
) -> String {
    for key in &[
        "GuideName",
        "name",
        "guide_name",
        "guideName",
        "title",
        "channel_name",
    ] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    format!("Channel {fallback_num}")
}

/// Extracts the XMLTV / EPG identifier.
fn extract_tvg_id(obj: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for key in &[
        "tvg_id",
        "tvg-id",
        "tvgId",
        "epg_channel_id",
        "epg_id",
        "epgId",
        "custom_sid",
    ] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Extracts the XMLTV display name.
fn extract_tvg_name(
    obj: &serde_json::Map<String, serde_json::Value>,
    guide_name: &str,
) -> Option<String> {
    for key in &["tvg_name", "tvg-name", "tvgName"] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    Some(guide_name.to_string())
}

/// Extracts the channel icon or logo URL.
fn extract_tvg_logo(obj: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for key in &[
        "tvg_logo",
        "tvg-logo",
        "tvgLogo",
        "stream_icon",
        "logo",
        "icon",
        "cover",
    ] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Extracts the channel category or group title.
fn extract_group_title(
    obj: &serde_json::Map<String, serde_json::Value>,
    inherited: Option<&str>,
) -> Option<String> {
    for key in &[
        "group_title",
        "group-title",
        "groupTitle",
        "category_name",
        "category_id",
        "group",
        "genre",
    ] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    inherited.map(|s| s.to_string())
}

/// Extracts the HD flag (1 for HD/UHD/4K/1080p, 0 for SD).
fn extract_hd(obj: &serde_json::Map<String, serde_json::Value>, guide_name: &str) -> u8 {
    for key in &["HD", "hd"] {
        if let Some(val) = obj.get(*key) {
            if let Some(b) = val.as_bool() {
                return if b { 1 } else { 0 };
            }
            if let Some(n) = val.as_i64() {
                return if n > 0 { 1 } else { 0 };
            }
            if let Some(n) = val.as_u64() {
                return if n > 0 { 1 } else { 0 };
            }
            if let Some(s) = val.as_str() {
                if s.trim() == "1" || s.eq_ignore_ascii_case("true") {
                    return 1;
                }
            }
        }
    }

    if let Some(badges) = obj.get("badges").and_then(|v| v.as_array()) {
        for b in badges {
            if let Some(s) = b.as_str() {
                let up = s.to_ascii_uppercase();
                if up.contains("HD")
                    || up.contains("4K")
                    || up.contains("UHD")
                    || up.contains("1080")
                    || up.contains("FHD")
                {
                    return 1;
                }
            }
        }
    }

    let up = guide_name.to_ascii_uppercase();
    if up.contains("HD")
        || up.contains("FHD")
        || up.contains("1080")
        || up.contains("4K")
        || up.contains("UHD")
        || up.contains("HEVC")
    {
        1
    } else {
        0
    }
}

/// Extracts favorite status (1 if favorite, 0 otherwise).
fn extract_favorite(obj: &serde_json::Map<String, serde_json::Value>) -> u8 {
    for key in &["Favorite", "favorite", "is_favorite"] {
        if let Some(val) = obj.get(*key) {
            if let Some(b) = val.as_bool() {
                return if b { 1 } else { 0 };
            }
            if let Some(n) = val.as_i64() {
                return if n > 0 { 1 } else { 0 };
            }
            if let Some(n) = val.as_u64() {
                return if n > 0 { 1 } else { 0 };
            }
            if let Some(s) = val.as_str() {
                if s.trim() == "1" || s.eq_ignore_ascii_case("true") {
                    return 1;
                }
            }
        }
    }
    0
}

/// Parses arbitrary catalog JSON formats (Xtream array, `/api/channels` items wrapper,
/// or `/api/entertainment/hub` curated live TV dictionary) into standardized `ChannelEntry` records.
pub fn parse_catalog_channels(value: &serde_json::Value, base_url: &str) -> Vec<ChannelEntry> {
    struct RawChannelItem<'a> {
        inherited_group: Option<String>,
        value: &'a serde_json::Value,
    }

    let mut raw_items: Vec<RawChannelItem> = Vec::new();

    if let Some(arr) = value.as_array() {
        for item in arr {
            raw_items.push(RawChannelItem {
                inherited_group: None,
                value: item,
            });
        }
    } else if let Some(map) = value.as_object() {
        if let Some(curated) = map.get("curated_live_tv") {
            if let Some(genre_map) = curated.as_object() {
                for (genre, genre_items) in genre_map {
                    let group_name = capitalize_first(genre);
                    if let Some(arr) = genre_items.as_array() {
                        for item in arr {
                            raw_items.push(RawChannelItem {
                                inherited_group: Some(group_name.clone()),
                                value: item,
                            });
                        }
                    }
                }
            } else if let Some(arr) = curated.as_array() {
                for item in arr {
                    raw_items.push(RawChannelItem {
                        inherited_group: None,
                        value: item,
                    });
                }
            }
        }

        // If curated_live_tv didn't yield items, inspect items/channels/data/streams wrappers
        if raw_items.is_empty() {
            for key in &["items", "channels", "data", "streams"] {
                if let Some(arr) = map.get(*key).and_then(|v| v.as_array()) {
                    for item in arr {
                        raw_items.push(RawChannelItem {
                            inherited_group: None,
                            value: item,
                        });
                    }
                    if !raw_items.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    let clean_base = base_url.trim_end_matches('/');
    let mut channels = Vec::with_capacity(raw_items.len());
    let mut seen_ids = HashSet::new();

    for (idx, raw) in raw_items.iter().enumerate() {
        let Some(obj) = raw.value.as_object() else {
            continue;
        };

        let guide_number = extract_guide_number(obj, idx);
        let guide_name = extract_guide_name(obj, &guide_number);
        let stream_id = extract_stream_id(obj).unwrap_or_else(|| guide_number.clone());

        if !seen_ids.insert(stream_id.clone()) {
            continue;
        }

        let stream_url = format!("{clean_base}/live/airlock/proxy/{stream_id}.ts");
        let hd = extract_hd(obj, &guide_name);
        let favorite = extract_favorite(obj);
        let tvg_id = extract_tvg_id(obj);
        let tvg_name = extract_tvg_name(obj, &guide_name);
        let tvg_logo = extract_tvg_logo(obj);
        let group_title = extract_group_title(obj, raw.inherited_group.as_deref());

        channels.push(ChannelEntry {
            guide_number,
            guide_name,
            stream_url,
            hd,
            favorite,
            tvg_id,
            tvg_name,
            tvg_logo,
            group_title,
        });
    }

    channels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xtream_channel_array() {
        let json_str = r#"[
            {
                "num": 1,
                "name": "Sky Sports Premier League HD",
                "stream_type": "live",
                "stream_id": 1001,
                "stream_icon": "http://img.test/sky.png",
                "epg_channel_id": "sky.sports.pl",
                "category_id": "Sports",
                "is_favorite": 1
            },
            {
                "num": 2,
                "name": "BBC One SD",
                "stream_type": "live",
                "stream_id": 1002,
                "stream_icon": "http://img.test/bbc.png",
                "epg_channel_id": "bbc.one",
                "category_id": "General",
                "is_favorite": 0,
                "hd": 0
            }
        ]"#;

        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let channels = parse_catalog_channels(&val, "http://127.0.0.1:8795");

        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0].guide_number, "1");
        assert_eq!(channels[0].guide_name, "Sky Sports Premier League HD");
        assert_eq!(
            channels[0].stream_url,
            "http://127.0.0.1:8795/live/airlock/proxy/1001.ts"
        );
        assert_eq!(channels[0].hd, 1);
        assert_eq!(channels[0].favorite, 1);
        assert_eq!(channels[0].tvg_id, Some("sky.sports.pl".to_string()));
        assert_eq!(
            channels[0].tvg_logo,
            Some("http://img.test/sky.png".to_string())
        );
        assert_eq!(channels[0].group_title, Some("Sports".to_string()));

        assert_eq!(channels[1].guide_number, "2");
        assert_eq!(channels[1].guide_name, "BBC One SD");
        assert_eq!(
            channels[1].stream_url,
            "http://127.0.0.1:8795/live/airlock/proxy/1002.ts"
        );
        assert_eq!(channels[1].hd, 0);
        assert_eq!(channels[1].favorite, 0);
    }

    #[test]
    fn test_parse_curated_hub_structure() {
        let json_str = r#"{
            "ok": true,
            "curated_live_tv": {
                "sports": [
                    {
                        "stream_id": 5001,
                        "name": "TNT Sports 1 HD",
                        "stream_icon": "http://img.test/tnt.png",
                        "epg_channel_id": "tnt.1",
                        "badges": ["HD", "50FPS"]
                    }
                ],
                "cinema": [
                    {
                        "stream_id": 6001,
                        "name": "Sky Cinema Premiere 4K",
                        "stream_icon": "http://img.test/cinema.png",
                        "epg_channel_id": "sky.cinema.prem"
                    }
                ]
            }
        }"#;

        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let channels = parse_catalog_channels(&val, "http://127.0.0.1:8795/");

        assert_eq!(channels.len(), 2);
        let sports = channels
            .iter()
            .find(|c| c.stream_url.contains("5001"))
            .unwrap();
        assert_eq!(sports.group_title, Some("Sports".to_string()));
        assert_eq!(sports.hd, 1);

        let cinema = channels
            .iter()
            .find(|c| c.stream_url.contains("6001"))
            .unwrap();
        assert_eq!(cinema.group_title, Some("Cinema".to_string()));
        assert_eq!(cinema.hd, 1);
    }
}
