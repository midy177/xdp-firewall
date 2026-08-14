use super::*;

#[tokio::test]
async fn dynamic_defense_update_persists_and_bumps_policy_version() {
    let (app, db) = test_router().await;
    let update = json!({
        "enabled": true,
        "ip_rate_limit_enabled": true,
        "ip_packets_per_second": 1234,
        "ip_burst": 2345,
        "flood_enabled": true,
        "flood_packets_per_second": 3456,
        "flood_burst": 4567,
        "flood_block_seconds": 89
    });

    let updated =
        response_json(send_json(&app, Method::PUT, "/dynamic-defense", update.clone()).await).await;
    assert_eq!(updated["version"], 1);
    assert_eq!(updated["data"]["ip_packets_per_second"], 1234);
    assert_eq!(updated["data"]["flood_block_seconds"], 89);
    let first_row = dynamic_defense::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap();

    let unchanged =
        response_json(send_json(&app, Method::PUT, "/dynamic-defense", update).await).await;
    assert_eq!(unchanged["version"], 1);
    let second_row = dynamic_defense::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_row.updated_at, first_row.updated_at);

    let fetched = response_json(send_empty(&app, Method::GET, "/dynamic-defense").await).await;
    assert_eq!(fetched["enabled"], true);
    assert_eq!(fetched["ip_rate_limit_enabled"], true);
    assert_eq!(fetched["ip_packets_per_second"], 1234);
    assert_eq!(fetched["ip_burst"], 2345);
    assert_eq!(fetched["flood_packets_per_second"], 3456);
    assert_eq!(fetched["flood_burst"], 4567);
    assert_eq!(fetched["flood_block_seconds"], 89);
}

#[tokio::test]
async fn seed_example_policy_returns_versioned_snapshot() {
    let (app, _db) = test_router().await;

    let seeded = response_json(send_empty(&app, Method::POST, "/policy/seed-example").await).await;

    assert_eq!(seeded["version"], seeded["data"]["version"]);
    assert_eq!(seeded["version"], 1);
    assert!(!seeded["data"]["rules"].as_array().unwrap().is_empty());
}
