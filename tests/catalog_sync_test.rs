#![forbid(unsafe_code)]

//! Integration tests verifying automated Live Channel Lineup & EPG Catalog Sync,
//! HDHomeRun `/lineup.json` descriptors, and `#EXTM3U` playlist generation.

use std::sync::Arc;
use std::time::Duration;

use airlock::engine::{CatalogSyncManager, ChannelEntry, LineupManager, create_lineup_router};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_catalog_sync_from_channels_endpoint_and_lineup_routes() {
    let mock_server = MockServer::start().await;

    // Upstream catalog service returns JSON list of channels
    let catalog_payload = serde_json::json!([
        {
            "stream_id": 101,
            "num": 1,
            "name": "Sky Sports Main Event HD",
            "stream_icon": "http://img.provider.com/sky_sports.png",
            "epg_channel_id": "sky.sports.main",
            "category_id": "Sports",
            "is_favorite": 1
        },
        {
            "stream_id": 202,
            "num": 2,
            "name": "HBO Max Cinema",
            "stream_icon": "http://img.provider.com/hbo.png",
            "epg_channel_id": "hbo.cinema",
            "category_id": "Cinema",
            "is_favorite": 0,
            "hd": 0
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/api/entertainment/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog_payload))
        .expect(1)
        .mount(&mock_server)
        .await;

    let lineup_base_url = "http://127.0.0.1:8795";
    let lineup_manager = Arc::new(LineupManager::new(lineup_base_url, "AIRLOCK_TEST_001"));
    let client = reqwest::Client::new();
    let sync_manager = Arc::new(CatalogSyncManager::new(
        Arc::clone(&lineup_manager),
        client.clone(),
        mock_server.uri(),
    ));

    // Execute sync from catalog
    let synced_count = sync_manager
        .sync_from_catalog()
        .await
        .expect("sync_from_catalog should succeed");
    assert_eq!(synced_count, 2);

    // Verify LineupManager state directly
    let channels = lineup_manager.get_lineup_json();
    assert_eq!(channels.len(), 2);

    let ch1 = &channels[0];
    assert_eq!(ch1.guide_number, "1");
    assert_eq!(ch1.guide_name, "Sky Sports Main Event HD");
    assert_eq!(
        ch1.stream_url,
        "http://127.0.0.1:8795/live/airlock/proxy/101.ts"
    );
    assert_eq!(ch1.hd, 1);
    assert_eq!(ch1.favorite, 1);
    assert_eq!(ch1.tvg_id.as_deref(), Some("sky.sports.main"));
    assert_eq!(
        ch1.tvg_logo.as_deref(),
        Some("http://img.provider.com/sky_sports.png")
    );
    assert_eq!(ch1.group_title.as_deref(), Some("Sports"));

    let ch2 = &channels[1];
    assert_eq!(ch2.guide_number, "2");
    assert_eq!(ch2.guide_name, "HBO Max Cinema");
    assert_eq!(
        ch2.stream_url,
        "http://127.0.0.1:8795/live/airlock/proxy/202.ts"
    );
    assert_eq!(ch2.hd, 0);
    assert_eq!(ch2.favorite, 0);
    assert_eq!(ch2.tvg_id.as_deref(), Some("hbo.cinema"));
    assert_eq!(
        ch2.tvg_logo.as_deref(),
        Some("http://img.provider.com/hbo.png")
    );
    assert_eq!(ch2.group_title.as_deref(), Some("Cinema"));

    // Spin up local Axum server with lineup router to verify HTTP endpoints
    let router = create_lineup_router(Arc::clone(&lineup_manager));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let local_addr = listener.local_addr().expect("retrieve local addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // 1. Verify /lineup.json endpoint
    let lineup_res = client
        .get(format!("http://{local_addr}/lineup.json"))
        .send()
        .await
        .expect("request /lineup.json");
    assert_eq!(lineup_res.status(), reqwest::StatusCode::OK);
    assert_eq!(
        lineup_res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );

    let fetched_lineup_bytes = lineup_res.bytes().await.expect("lineup body bytes");
    let fetched_lineup: Vec<ChannelEntry> =
        serde_json::from_slice(&fetched_lineup_bytes).expect("deserialize lineup json");
    assert_eq!(fetched_lineup.len(), 2);
    assert_eq!(fetched_lineup[0].guide_name, "Sky Sports Main Event HD");
    assert_eq!(
        fetched_lineup[0].stream_url,
        "http://127.0.0.1:8795/live/airlock/proxy/101.ts"
    );
    assert_eq!(fetched_lineup[1].guide_name, "HBO Max Cinema");

    // 2. Verify /playlist.m3u8 endpoint
    let m3u_res = client
        .get(format!("http://{local_addr}/playlist.m3u8"))
        .send()
        .await
        .expect("request /playlist.m3u8");
    assert_eq!(m3u_res.status(), reqwest::StatusCode::OK);
    assert_eq!(
        m3u_res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("audio/x-mpegurl; charset=utf-8")
    );

    let m3u_body = m3u_res.text().await.expect("m3u text");
    assert!(m3u_body.starts_with("#EXTM3U"));

    // Check channel 1 tags and URL
    assert!(m3u_body.contains(r#"tvg-id="sky.sports.main""#));
    assert!(m3u_body.contains(r#"tvg-name="Sky Sports Main Event HD""#));
    assert!(m3u_body.contains(r#"tvg-logo="http://img.provider.com/sky_sports.png""#));
    assert!(m3u_body.contains(r#"group-title="Sports",Sky Sports Main Event HD"#));
    assert!(m3u_body.contains("http://127.0.0.1:8795/live/airlock/proxy/101.ts"));

    // Check channel 2 tags and URL
    assert!(m3u_body.contains(r#"tvg-id="hbo.cinema""#));
    assert!(m3u_body.contains(r#"tvg-name="HBO Max Cinema""#));
    assert!(m3u_body.contains(r#"tvg-logo="http://img.provider.com/hbo.png""#));
    assert!(m3u_body.contains(r#"group-title="Cinema",HBO Max Cinema"#));
    assert!(m3u_body.contains("http://127.0.0.1:8795/live/airlock/proxy/202.ts"));
}

#[tokio::test]
async fn test_catalog_sync_curated_entertainment_hub_fallback() {
    let mock_server = MockServer::start().await;

    // First candidate /api/entertainment/channels returns 404
    Mock::given(method("GET"))
        .and(path("/api/entertainment/channels"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Second candidate /api/entertainment/hub returns curated dictionary
    let hub_payload = serde_json::json!({
        "ok": true,
        "curated_live_tv": {
            "sports": [
                {
                    "stream_id": 303,
                    "name": "TNT Sports 1 UHD",
                    "stream_icon": "http://img.test/tnt.png",
                    "epg_channel_id": "tnt.sports.1",
                    "badges": ["4K", "50FPS"]
                }
            ],
            "cinema": [
                {
                    "stream_id": 404,
                    "name": "Sky Cinema Premiere HD",
                    "stream_icon": "http://img.test/sky_cinema.png",
                    "epg_channel_id": "sky.cinema.prem"
                }
            ]
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/entertainment/hub"))
        .respond_with(ResponseTemplate::new(200).set_body_json(hub_payload))
        .mount(&mock_server)
        .await;

    let lineup_manager = Arc::new(LineupManager::new(
        "http://127.0.0.1:8795",
        "AIRLOCK_TEST_002",
    ));
    let client = reqwest::Client::new();
    let sync_manager =
        CatalogSyncManager::new(Arc::clone(&lineup_manager), client, mock_server.uri());

    let count = sync_manager
        .sync_from_catalog()
        .await
        .expect("sync hub fallback should succeed");
    assert_eq!(count, 2);

    let channels = lineup_manager.get_lineup_json();
    let tnt = channels
        .iter()
        .find(|c| c.stream_url.contains("303"))
        .expect("TNT channel found");
    assert_eq!(tnt.guide_name, "TNT Sports 1 UHD");
    assert_eq!(tnt.group_title.as_deref(), Some("Sports"));
    assert_eq!(tnt.hd, 1);
    assert_eq!(tnt.tvg_id.as_deref(), Some("tnt.sports.1"));

    let cinema = channels
        .iter()
        .find(|c| c.stream_url.contains("404"))
        .expect("Cinema channel found");
    assert_eq!(cinema.guide_name, "Sky Cinema Premiere HD");
    assert_eq!(cinema.group_title.as_deref(), Some("Cinema"));
    assert_eq!(cinema.hd, 1);
}

#[tokio::test]
async fn test_catalog_sync_xtream_player_api_fallback() {
    let mock_server = MockServer::start().await;

    // Candidate 1 & 2 return 404
    Mock::given(method("GET"))
        .and(path("/api/entertainment/channels"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/entertainment/hub"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Xtream endpoint matches
    let xtream_payload = serde_json::json!([
        {
            "num": 42,
            "name": "Eurosport 1 HD",
            "stream_type": "live",
            "stream_id": 999,
            "stream_icon": "http://img.test/eurosport.png",
            "epg_channel_id": "eurosport.1",
            "category_name": "Sports"
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/player_api.php"))
        .and(query_param("action", "get_live_streams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(xtream_payload))
        .mount(&mock_server)
        .await;

    let lineup_manager = Arc::new(LineupManager::new(
        "http://127.0.0.1:8795",
        "AIRLOCK_TEST_003",
    ));
    let client = reqwest::Client::new();
    let sync_manager =
        CatalogSyncManager::new(Arc::clone(&lineup_manager), client, mock_server.uri());

    let count = sync_manager
        .sync_from_catalog()
        .await
        .expect("sync xtream fallback should succeed");
    assert_eq!(count, 1);

    let channels = lineup_manager.get_lineup_json();
    assert_eq!(channels[0].guide_number, "42");
    assert_eq!(channels[0].guide_name, "Eurosport 1 HD");
    assert_eq!(
        channels[0].stream_url,
        "http://127.0.0.1:8795/live/airlock/proxy/999.ts"
    );
    assert_eq!(channels[0].group_title.as_deref(), Some("Sports"));
}

#[tokio::test]
async fn test_periodic_catalog_sync_lifecycle() {
    let mock_server = MockServer::start().await;

    // Initial response with 1 channel
    let initial_payload = serde_json::json!([
        {
            "stream_id": 501,
            "num": 1,
            "name": "Initial Channel HD"
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/api/entertainment/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(initial_payload))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second response with 2 channels
    let updated_payload = serde_json::json!([
        {
            "stream_id": 501,
            "num": 1,
            "name": "Initial Channel HD"
        },
        {
            "stream_id": 502,
            "num": 2,
            "name": "Second Channel HD"
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/api/entertainment/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(updated_payload))
        .mount(&mock_server)
        .await;

    let lineup_manager = Arc::new(LineupManager::new(
        "http://127.0.0.1:8795",
        "AIRLOCK_TEST_004",
    ));
    let client = reqwest::Client::new();
    let sync_manager = Arc::new(CatalogSyncManager::new(
        Arc::clone(&lineup_manager),
        client,
        mock_server.uri(),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn periodic background sync task with very short 40ms interval
    let handle = sync_manager.spawn_periodic_sync(Duration::from_millis(40), shutdown_rx);

    // Give it a moment to run initial sync
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(lineup_manager.get_lineup_json().len(), 1);

    // Wait for next periodic interval to trigger
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(lineup_manager.get_lineup_json().len(), 2);

    // Signal graceful shutdown
    shutdown_tx.send(true).expect("send shutdown signal");

    // Background task should terminate within 100ms
    tokio::time::timeout(Duration::from_millis(200), handle)
        .await
        .expect("periodic sync task should join before timeout")
        .expect("task join handle ok");
}

#[tokio::test]
async fn test_catalog_sync_server_error_reporting() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/entertainment/channels"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let lineup_manager = Arc::new(LineupManager::new(
        "http://127.0.0.1:8795",
        "AIRLOCK_TEST_005",
    ));
    let client = reqwest::Client::new();
    let sync_manager =
        CatalogSyncManager::new(Arc::clone(&lineup_manager), client, mock_server.uri());

    let res = sync_manager.sync_from_catalog().await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        matches!(err, airlock::error::AirlockError::Ingest(airlock::error::IngestError::BadStatus(status)) if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR)
    );
}
