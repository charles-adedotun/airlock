#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Parser;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::security::RedactedString;

/// Stream arbitration policy on single-tuner conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConflictPolicy {
    /// Reject new stream requests if an upstream connection is already active.
    #[default]
    Reject,
    /// Preempt existing stream requests in favor of the newly requested channel switch.
    Preempt,
}

impl FromStr for ConflictPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "reject" => Ok(ConflictPolicy::Reject),
            "preempt" => Ok(ConflictPolicy::Preempt),
            other => Err(format!(
                "invalid conflict policy: '{other}', expected 'reject' or 'preempt'"
            )),
        }
    }
}

impl std::fmt::Display for ConflictPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictPolicy::Reject => write!(f, "reject"),
            ConflictPolicy::Preempt => write!(f, "preempt"),
        }
    }
}

/// Server binding and upstream routing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address and port for the HTTP daemon.
    pub listen: SocketAddr,
    /// Target upstream IPTV / media provider base URL.
    pub upstream: String,
    /// Optional upstream IPTV provider username.
    pub upstream_user: Option<RedactedString>,
    /// Optional upstream IPTV provider password.
    pub upstream_pass: Option<RedactedString>,
    /// Internal Python catalog & metadata service base URL.
    pub catalog_upstream: String,
    /// Allow private RFC 1918 and Tailscale CGNAT addresses for upstream tuners.
    pub allow_private_upstream: bool,
    /// Optional outbound proxy (e.g., socks5h://127.0.0.1:1080) for upstream provider access.
    pub upstream_proxy: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 8795)),
            upstream: "http://stream.example.com".to_string(),
            upstream_user: None,
            upstream_pass: None,
            catalog_upstream: "http://127.0.0.1:8794".to_string(),
            allow_private_upstream: false,
            upstream_proxy: None,
        }
    }
}

impl ServerConfig {
    /// Returns the configured upstream credentials as `(&str, &str)`,
    /// falling back to legacy defaults `("airlock", "proxy")` if unconfigured.
    pub fn upstream_credentials(&self) -> (&str, &str) {
        let user = self.upstream_user.as_deref().unwrap_or("airlock");
        let pass = self.upstream_pass.as_deref().unwrap_or("proxy");
        (user, pass)
    }
}

/// Storage, rolling DVR cache, and disk headroom configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Root directory for the rolling DVR and VOD cache.
    pub cache_dir: PathBuf,
    /// Maximum rolling storage quota in gigabytes.
    pub max_storage_gb: u64,
    /// Minimum emergency free disk space floor in gigabytes.
    pub min_disk_free_gb: u64,
    /// Rolling DVR segment duration in seconds.
    pub segment_duration_secs: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from("~/.cache/airlock/media"),
            max_storage_gb: 100,
            min_disk_free_gb: 10,
            segment_duration_secs: 300,
        }
    }
}

impl StorageConfig {
    /// Resolves the cache directory, expanding `~` to the user's HOME directory if present.
    pub fn resolved_cache_dir(&self) -> PathBuf {
        expand_tilde(&self.cache_dir)
    }
}

/// Streaming latency, tuner arbitration, and timeshift buffer configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamingConfig {
    /// Target buffer latency for live sports in seconds.
    pub sports_latency_sec: f64,
    /// Stream arbitration policy on channel conflict.
    pub conflict_policy: ConflictPolicy,
    /// Maximum hours of rolling timeshift buffer retained on disk.
    pub timeshift_max_hours: u32,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            sports_latency_sec: 2.0,
            conflict_policy: ConflictPolicy::Reject,
            timeshift_max_hours: 2,
        }
    }
}

/// Comprehensive schema deserializable from `airlock.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AirlockConfigFile {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub streaming: StreamingConfig,
}

/// Convenience alias for `AirlockConfigFile`.
pub type AirlockConfig = AirlockConfigFile;

impl AirlockConfigFile {
    /// Parse configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(ConfigError::Toml)
    }

    /// Serialize configuration to a formatted TOML string.
    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Merges CLI arguments into this configuration in place.
    /// CLI arguments override environment variables, which override TOML values, which override defaults.
    pub fn merge_with_cli(&mut self, cli: &CliArgs) {
        if let Some(listen) = cli.listen {
            self.server.listen = listen;
        }
        if let Some(ref upstream) = cli.upstream {
            self.server.upstream = upstream.clone();
        }
        if let Some(ref user) = cli.upstream_user {
            self.server.upstream_user = Some(user.clone());
        }
        if let Some(ref pass) = cli.upstream_pass {
            self.server.upstream_pass = Some(pass.clone());
        }
        if let Some(ref catalog_upstream) = cli.catalog_upstream {
            self.server.catalog_upstream = catalog_upstream.clone();
        }
        if let Some(allow_private) = cli.allow_private_upstream {
            self.server.allow_private_upstream = allow_private;
        }
        if let Some(ref proxy) = cli.upstream_proxy {
            self.server.upstream_proxy = Some(proxy.clone());
        }

        if let Some(ref cache_dir) = cli.cache_dir {
            self.storage.cache_dir = cache_dir.clone();
        }
        if let Some(max_storage) = cli.max_storage_gb {
            self.storage.max_storage_gb = max_storage;
        }
        if let Some(min_disk_free) = cli.min_disk_free_gb {
            self.storage.min_disk_free_gb = min_disk_free;
        }
        if let Some(segment_duration) = cli.segment_duration_secs {
            self.storage.segment_duration_secs = segment_duration;
        }

        if let Some(sports_latency) = cli.sports_latency_sec {
            self.streaming.sports_latency_sec = sports_latency;
        }
        if let Some(conflict_policy) = cli.conflict_policy {
            self.streaming.conflict_policy = conflict_policy;
        }
        if let Some(timeshift_hours) = cli.timeshift_max_hours {
            self.streaming.timeshift_max_hours = timeshift_hours;
        }
    }

    /// Returns a new configuration with CLI arguments merged in.
    pub fn merged_with_cli(mut self, cli: &CliArgs) -> Self {
        self.merge_with_cli(cli);
        self
    }
}

impl FromStr for AirlockConfigFile {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_toml_str(s)
    }
}

/// Helper function to merge CLI `Args` with `AirlockConfigFile`.
pub fn merge_args(config: &mut AirlockConfigFile, args: &CliArgs) {
    config.merge_with_cli(args);
}

/// Helper function to merge CLI `Args` with `AirlockConfigFile`.
pub fn merge_config_with_cli(config: &mut AirlockConfigFile, args: &CliArgs) {
    config.merge_with_cli(args);
}

/// Command line arguments and environment variable overrides for Airlock.
#[derive(Parser, Debug, Clone, Default, PartialEq)]
#[command(
    name = "airlock",
    about = "High-Throughput Read-Ahead Streaming Proxy, Jitter Shield & Single-Upstream Arbiter",
    version
)]
pub struct CliArgs {
    /// Path to optional airlock.toml configuration file
    #[arg(short = 'c', long = "config", env = "AIRLOCK_CONFIG")]
    pub config: Option<PathBuf>,

    /// Bind address for the HTTP streaming and control server
    #[arg(short = 'l', long = "listen", env = "AIRLOCK_LISTEN")]
    pub listen: Option<SocketAddr>,

    /// Target upstream IPTV / media provider base URL
    #[arg(short = 'u', long = "upstream", env = "AIRLOCK_UPSTREAM")]
    pub upstream: Option<String>,

    /// Target upstream IPTV username
    #[arg(long = "upstream-user", env = "AIRLOCK_UPSTREAM_USER")]
    pub upstream_user: Option<RedactedString>,

    /// Target upstream IPTV password
    #[arg(long = "upstream-pass", env = "AIRLOCK_UPSTREAM_PASS")]
    pub upstream_pass: Option<RedactedString>,

    /// Optional outbound proxy URL (e.g. socks5h://127.0.0.1:1080) for upstream provider access
    #[arg(long = "upstream-proxy", env = "AIRLOCK_UPSTREAM_PROXY")]
    pub upstream_proxy: Option<String>,

    /// Internal Python catalog & metadata service base URL
    #[arg(long = "catalog-upstream", env = "AIRLOCK_CATALOG_UPSTREAM")]
    pub catalog_upstream: Option<String>,

    /// Root directory for the rolling DVR and VOD cache
    #[arg(long = "cache-dir", env = "AIRLOCK_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Maximum rolling storage quota in gigabytes (50 to 200 GB)
    #[arg(long = "max-storage-gb", env = "AIRLOCK_MAX_STORAGE_GB")]
    pub max_storage_gb: Option<u64>,

    /// Minimum emergency free disk space floor in gigabytes
    #[arg(long = "min-disk-free-gb", env = "AIRLOCK_MIN_DISK_FREE_GB")]
    pub min_disk_free_gb: Option<u64>,

    /// Segment duration in seconds
    #[arg(long = "segment-duration-secs", env = "AIRLOCK_SEGMENT_DURATION_SECS")]
    pub segment_duration_secs: Option<u64>,

    /// Target buffer latency for live sports in seconds
    #[arg(long = "sports-latency-sec", env = "AIRLOCK_SPORTS_LATENCY_SEC")]
    pub sports_latency_sec: Option<f64>,

    /// Stream conflict policy ("reject" or "preempt")
    #[arg(long = "conflict-policy", env = "AIRLOCK_CONFLICT_POLICY")]
    pub conflict_policy: Option<ConflictPolicy>,

    /// Timeshift buffer retention in hours
    #[arg(long = "timeshift-max-hours", env = "AIRLOCK_TIMESHIFT_MAX_HOURS")]
    pub timeshift_max_hours: Option<u32>,

    /// Allow private RFC 1918 and Tailscale CGNAT addresses for upstream tuners
    #[arg(
        long = "allow-private-upstream",
        env = "AIRLOCK_ALLOW_PRIVATE_UPSTREAM",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    pub allow_private_upstream: Option<bool>,
}

/// Alias for `CliArgs` conforming to standard naming.
pub type Args = CliArgs;

/// Configuration loading, parsing, and validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error reading configuration file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse TOML configuration from '{path}': {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("Failed to deserialize TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Configuration validation error: {0}")]
    Validation(String),
}

/// Expands leading `~` or `~/` in a path using the `HOME` environment variable.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(suffix) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(suffix);
        }
    }
    path.to_path_buf()
}

/// Loads and deserializes an `AirlockConfigFile` from an explicit filesystem path.
pub fn load_config_from_path(path: &Path) -> Result<AirlockConfigFile, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|err| ConfigError::Io {
        path: path.to_path_buf(),
        source: err,
    })?;

    toml::from_str(&content).map_err(|err| ConfigError::Parse {
        path: path.to_path_buf(),
        source: err,
    })
}

/// Resolves the configuration file path according to the standard discovery order:
/// 1. `explicit_path` (if provided via `--config <path>`)
/// 2. `AIRLOCK_CONFIG` environment variable
/// 3. `./airlock.toml` (current working directory)
/// 4. `/etc/airlock/airlock.toml`
/// 5. None if no candidate file exists.
pub fn resolve_config_path(explicit_path: Option<&Path>) -> Option<PathBuf> {
    // 1. explicit_path
    if let Some(path) = explicit_path {
        if path.is_file() {
            return Some(path.to_path_buf());
        }
        // If an explicit path was provided but does not exist, do not fall through to implicit paths.
        return None;
    }

    // 2. AIRLOCK_CONFIG environment variable
    if let Ok(env_path) = std::env::var("AIRLOCK_CONFIG") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
            }
            // If explicit env var was set but does not exist, do not fall through to generic paths.
            return None;
        }
    }

    // 3. ./airlock.toml (current working directory)
    let cwd_path = Path::new("./airlock.toml");
    if cwd_path.is_file() {
        return Some(cwd_path.to_path_buf());
    }

    // 4. /etc/airlock/airlock.toml
    let etc_path = Path::new("/etc/airlock/airlock.toml");
    if etc_path.is_file() {
        return Some(etc_path.to_path_buf());
    }

    // 5. Default configuration if no file exists
    None
}

/// Loads configuration following the discovery order:
/// 1. `explicit_path` (if provided via `--config <path>`)
/// 2. `AIRLOCK_CONFIG` environment variable
/// 3. `./airlock.toml` (current working directory)
/// 4. `/etc/airlock/airlock.toml`
/// 5. Default configuration if no file exists.
pub fn load_config_with_fallback(
    explicit_path: Option<&Path>,
) -> Result<AirlockConfigFile, ConfigError> {
    if let Some(path) = resolve_config_path(explicit_path) {
        load_config_from_path(&path)
    } else {
        Ok(AirlockConfigFile::default())
    }
}
