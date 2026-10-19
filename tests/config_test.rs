#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use airlock::config::{
    AirlockConfigFile, CliArgs, ConfigError, ConflictPolicy, expand_tilde, load_config_from_path,
    load_config_with_fallback, merge_args, merge_config_with_cli,
};

#[test]
fn test_parse_sample_toml_config_into_typed_structs() {
    let sample = r#"
[server]
listen = "0.0.0.0:8795"
upstream = "http://line.ottcst.org"
catalog_upstream = "http://127.0.0.1:8794"
allow_private_upstream = false

[storage]
cache_dir = "~/.cache/airlock/media"
max_storage_gb = 100
min_disk_free_gb = 10
segment_duration_secs = 300

[streaming]
sports_latency_sec = 2.0
conflict_policy = "reject" # "reject" | "preempt"
timeshift_max_hours = 2
"#;

    let config = AirlockConfigFile::from_toml_str(sample)
        .expect("sample TOML config must parse successfully");

    let expected_listen: SocketAddr = "0.0.0.0:8795"
        .parse()
        .expect("listen address must be a valid SocketAddr");

    assert_eq!(config.server.listen, expected_listen);
    assert_eq!(config.server.upstream, "http://line.ottcst.org");
    assert_eq!(config.server.catalog_upstream, "http://127.0.0.1:8794");
    assert!(!config.server.allow_private_upstream);

    assert_eq!(
        config.storage.cache_dir,
        PathBuf::from("~/.cache/airlock/media")
    );
    assert_eq!(config.storage.max_storage_gb, 100);
    assert_eq!(config.storage.min_disk_free_gb, 10);
    assert_eq!(config.storage.segment_duration_secs, 300);

    assert!((config.streaming.sports_latency_sec - 2.0).abs() < f64::EPSILON);
    assert_eq!(config.streaming.conflict_policy, ConflictPolicy::Reject);
    assert_eq!(config.streaming.timeshift_max_hours, 2);
}

#[test]
fn test_parse_preempt_conflict_policy() {
    let sample = r#"
[streaming]
sports_latency_sec = 1.8
conflict_policy = "preempt"
timeshift_max_hours = 4
"#;

    let config = AirlockConfigFile::from_toml_str(sample)
        .expect("partial TOML with preempt conflict policy should parse");

    assert_eq!(config.streaming.conflict_policy, ConflictPolicy::Preempt);
    assert!((config.streaming.sports_latency_sec - 1.8).abs() < f64::EPSILON);
    assert_eq!(config.streaming.timeshift_max_hours, 4);

    // Other sections fall back to defaults
    assert_eq!(config.server.listen, SocketAddr::from(([0, 0, 0, 0], 8795)));
    assert_eq!(config.storage.max_storage_gb, 100);
}

#[test]
fn test_missing_file_gracefully_falling_back_to_defaults() {
    // 1. None explicit_path falls back to defaults when no default files exist
    let default_config = load_config_with_fallback(None)
        .expect("missing file with None explicit_path must gracefully fall back to defaults");
    assert_eq!(default_config, AirlockConfigFile::default());

    // 2. Non-existent explicit path also falls back to defaults gracefully
    let non_existent = Path::new("tests/fixtures/definitely_missing_airlock_987654.toml");
    let fallback_config = load_config_with_fallback(Some(non_existent))
        .expect("missing file with explicit path must gracefully fall back to defaults");
    assert_eq!(fallback_config, AirlockConfigFile::default());

    // Verify key defaults
    assert_eq!(
        default_config.server.listen,
        SocketAddr::from(([0, 0, 0, 0], 8795))
    );
    assert_eq!(default_config.server.upstream, "http://line.ottcst.org");
    assert_eq!(
        default_config.server.catalog_upstream,
        "http://127.0.0.1:8794"
    );
    assert!(!default_config.server.allow_private_upstream);
    assert_eq!(default_config.storage.max_storage_gb, 100);
    assert_eq!(default_config.storage.min_disk_free_gb, 10);
    assert_eq!(default_config.storage.segment_duration_secs, 300);
    assert!((default_config.streaming.sports_latency_sec - 2.0).abs() < f64::EPSILON);
    assert_eq!(
        default_config.streaming.conflict_policy,
        ConflictPolicy::Reject
    );
    assert_eq!(default_config.streaming.timeshift_max_hours, 2);
}

#[test]
fn test_custom_paths_loading_successfully() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join(format!(
        "airlock_custom_test_{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));

    let custom_toml = r#"
[server]
listen = "127.0.0.1:9095"
upstream = "http://upstream.provider.test"
catalog_upstream = "http://10.10.10.10:8794"
allow_private_upstream = true

[storage]
cache_dir = "/tmp/airlock_custom_media"
max_storage_gb = 175
min_disk_free_gb = 20
segment_duration_secs = 600

[streaming]
sports_latency_sec = 1.25
conflict_policy = "preempt"
timeshift_max_hours = 6
"#;

    std::fs::write(&file_path, custom_toml).expect("writing temporary custom config must succeed");

    // Load with load_config_with_fallback
    let config = load_config_with_fallback(Some(&file_path))
        .expect("loading from custom path via load_config_with_fallback must succeed");

    let expected_listen: SocketAddr = "127.0.0.1:9095".parse().expect("listen address must parse");

    assert_eq!(config.server.listen, expected_listen);
    assert_eq!(config.server.upstream, "http://upstream.provider.test");
    assert_eq!(config.server.catalog_upstream, "http://10.10.10.10:8794");
    assert!(config.server.allow_private_upstream);
    assert_eq!(
        config.storage.cache_dir,
        PathBuf::from("/tmp/airlock_custom_media")
    );
    assert_eq!(config.storage.max_storage_gb, 175);
    assert_eq!(config.storage.min_disk_free_gb, 20);
    assert_eq!(config.storage.segment_duration_secs, 600);
    assert!((config.streaming.sports_latency_sec - 1.25).abs() < f64::EPSILON);
    assert_eq!(config.streaming.conflict_policy, ConflictPolicy::Preempt);
    assert_eq!(config.streaming.timeshift_max_hours, 6);

    // Also test direct load_config_from_path
    let direct_config =
        load_config_from_path(&file_path).expect("direct loading from custom path must succeed");
    assert_eq!(direct_config, config);

    let _ = std::fs::remove_file(&file_path);
}

#[test]
fn test_precedence_merging_cli_args_override_config_file_values() {
    let base_toml = r#"
[server]
listen = "0.0.0.0:8795"
upstream = "http://line.ottcst.org"
catalog_upstream = "http://127.0.0.1:8794"
allow_private_upstream = false

[storage]
cache_dir = "~/.cache/airlock/media"
max_storage_gb = 100
min_disk_free_gb = 10
segment_duration_secs = 300

[streaming]
sports_latency_sec = 2.0
conflict_policy = "reject"
timeshift_max_hours = 2
"#;

    let mut config = AirlockConfigFile::from_toml_str(base_toml)
        .expect("base configuration must parse successfully");

    let override_listen: SocketAddr = "10.0.0.1:7777"
        .parse()
        .expect("override listen address must parse");

    // CLI args specify overrides for listen, max_storage_gb, conflict_policy, and allow_private_upstream.
    // Non-overridden options are None.
    let cli = CliArgs {
        config: None,
        listen: Some(override_listen),
        upstream: None,
        catalog_upstream: None,
        cache_dir: Some(PathBuf::from("/mnt/fast_nvme/airlock")),
        max_storage_gb: Some(190),
        min_disk_free_gb: None,
        segment_duration_secs: None,
        sports_latency_sec: Some(1.2),
        conflict_policy: Some(ConflictPolicy::Preempt),
        timeshift_max_hours: None,
        allow_private_upstream: Some(true),
    };

    merge_config_with_cli(&mut config, &cli);

    // Overridden fields must match CLI values
    assert_eq!(config.server.listen, override_listen);
    assert!(config.server.allow_private_upstream);
    assert_eq!(
        config.storage.cache_dir,
        PathBuf::from("/mnt/fast_nvme/airlock")
    );
    assert_eq!(config.storage.max_storage_gb, 190);
    assert!((config.streaming.sports_latency_sec - 1.2).abs() < f64::EPSILON);
    assert_eq!(config.streaming.conflict_policy, ConflictPolicy::Preempt);

    // Non-overridden fields must preserve original TOML values
    assert_eq!(config.server.upstream, "http://line.ottcst.org");
    assert_eq!(config.server.catalog_upstream, "http://127.0.0.1:8794");
    assert_eq!(config.storage.min_disk_free_gb, 10);
    assert_eq!(config.storage.segment_duration_secs, 300);
    assert_eq!(config.streaming.timeshift_max_hours, 2);

    // Also test merge_args wrapper
    let mut config2 =
        AirlockConfigFile::from_toml_str(base_toml).expect("base configuration must parse");
    merge_args(&mut config2, &cli);
    assert_eq!(config, config2);
}

#[test]
fn test_invalid_toml_file_returns_parse_error() {
    let temp_dir = std::env::temp_dir();
    let bad_path = temp_dir.join(format!(
        "airlock_bad_test_{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));

    std::fs::write(&bad_path, "invalid_toml = = [unclosed").expect("writing bad file must succeed");

    let result = load_config_from_path(&bad_path);
    assert!(matches!(result, Err(ConfigError::Parse { .. })));

    let result_fallback = load_config_with_fallback(Some(&bad_path));
    assert!(matches!(result_fallback, Err(ConfigError::Parse { .. })));

    let _ = std::fs::remove_file(&bad_path);
}

#[test]
fn test_direct_load_non_existent_file_returns_io_error() {
    let non_existent = Path::new("tests/fixtures/does_not_exist_ever_123.toml");
    let result = load_config_from_path(non_existent);
    assert!(matches!(result, Err(ConfigError::Io { .. })));
}

#[test]
fn test_conflict_policy_from_str_and_display() {
    let reject = ConflictPolicy::from_str("reject").expect("must parse 'reject'");
    assert_eq!(reject, ConflictPolicy::Reject);
    assert_eq!(format!("{reject}"), "reject");

    let preempt =
        ConflictPolicy::from_str("PREEMPT").expect("must parse case-insensitive 'preempt'");
    assert_eq!(preempt, ConflictPolicy::Preempt);
    assert_eq!(format!("{preempt}"), "preempt");

    let err = ConflictPolicy::from_str("unknown_policy");
    assert!(err.is_err());
}

#[test]
fn test_expand_tilde() {
    let regular = Path::new("/var/media/airlock");
    assert_eq!(expand_tilde(regular), PathBuf::from("/var/media/airlock"));

    let tilde_path = Path::new("~/airlock_test_dir");
    let expanded = expand_tilde(tilde_path);
    if let Ok(home) = std::env::var("HOME") {
        assert_eq!(expanded, PathBuf::from(home).join("airlock_test_dir"));
    }
}
