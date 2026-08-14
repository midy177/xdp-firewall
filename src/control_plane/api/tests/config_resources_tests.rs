use super::*;

#[tokio::test]
async fn config_queries_and_field_deletes_support_stable_resources() {
    let (app, db) = test_router().await;
    create_test_config_resources(&app).await;

    let countries = get_json(&app, "/geo-countries?country=CN&action=drop&enabled=true").await;
    assert_eq!(countries["total"], 1);
    let threats = get_json(&app, "/threat-sources?format=cidr&enabled=true").await;
    assert_eq!(threats["total"], 1);
    insert_test_threat_state(&db, threats["items"][0]["name"].as_str().unwrap()).await;
    let limits = get_json(
        &app,
        "/dynamic-rate-limits?protocol=tcp&port=443&priority=10",
    )
    .await;
    assert_eq!(limits["total"], 1);
    let trusted = get_json(&app, "/trusted-cidrs?cidr=10.1.2.99/8").await;
    assert_eq!(trusted["total"], 1);

    let deleted =
        delete_empty_json(&app, "/geo-countries?country=cn&action=deny&enabled=true").await;
    assert_eq!(deleted["data"]["deleted"], 1);
    let deleted = delete_empty_json(&app, "/threat-sources?name=test-feed").await;
    assert_eq!(deleted["data"]["deleted"], 1);
    assert_eq!(persisted_threat_state_count(&db).await, 0);
    let deleted = delete_empty_json(
        &app,
        "/dynamic-rate-limits?enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000",
    )
    .await;
    assert_eq!(deleted["data"]["deleted"], 1);
    let deleted = delete_empty_json(&app, "/trusted-cidrs?cidr=10.1.2.99/8").await;
    assert_eq!(deleted["data"]["deleted"], 1);
}

#[tokio::test]
async fn trusted_cidr_upsert_preserves_updated_at_when_unchanged() {
    let (app, db) = test_router().await;
    let body = json!({
        "cidr": "10.1.2.3/8",
        "enabled": true,
        "comment": "office"
    });

    let created = post_json(&app, "/trusted-cidrs", body.clone()).await;
    assert_eq!(created["version"], 1);
    let first = load_trusted_cidr(&db, "10.0.0.0/8").await;

    let unchanged = post_json(&app, "/trusted-cidrs", body).await;
    assert_eq!(unchanged["version"], 1);
    let second = load_trusted_cidr(&db, "10.0.0.0/8").await;
    assert_eq!(second.updated_at, first.updated_at);

    let changed = post_json(
        &app,
        "/trusted-cidrs",
        json!({
            "cidr": "10.1.2.3/8",
            "enabled": false,
            "comment": "office"
        }),
    )
    .await;
    assert_eq!(changed["version"], 2);
}

#[tokio::test]
async fn trusted_cidr_batch_returns_ok_when_all_items_are_unchanged() {
    let (app, _db) = test_router().await;
    let body = json!({
        "items": [
            {"cidr": "10.1.2.3/8", "enabled": true, "comment": "office"},
            {"cidr": "192.0.2.10/24", "enabled": false}
        ]
    });

    let created_response =
        send_json(&app, Method::POST, "/trusted-cidrs/batch", body.clone()).await;
    assert_eq!(created_response.status(), StatusCode::CREATED);
    let created = response_json(created_response).await;
    assert_eq!(created["version"], 1);

    let unchanged_response = send_json(&app, Method::POST, "/trusted-cidrs/batch", body).await;
    assert_eq!(unchanged_response.status(), StatusCode::OK);
    let unchanged = response_json(unchanged_response).await;
    assert_eq!(unchanged["version"], 1);
}

#[tokio::test]
async fn disabled_config_resource_changes_do_not_bump_policy_version() {
    let (app, _db) = test_router().await;

    let rule = response_json(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "rule_key": "disabled-rule",
                "enabled": false,
                "priority": 10,
                "action": "deny",
                "cidr": "203.0.113.0/24",
                "protocol": "tcp",
                "port": 443
            }),
        )
        .await,
    )
    .await;
    assert_eq!(rule["version"], 0);
    let deleted_rule = delete_empty_json(&app, "/rules?rule_key=disabled-rule").await;
    assert_eq!(deleted_rule["version"], 0);

    let country = post_json(
        &app,
        "/geo-countries",
        json!({"enabled": false, "country": "cn", "action": "deny"}),
    )
    .await;
    assert_eq!(country["version"], 0);
    let deleted_country =
        delete_empty_json(&app, "/geo-countries?enabled=false&country=cn&action=deny").await;
    assert_eq!(deleted_country["version"], 0);

    let limit = post_json(
        &app,
        "/dynamic-rate-limits",
        json!({
            "enabled": false,
            "priority": 10,
            "protocol": "tcp",
            "port": 443,
            "packets_per_second": 1000,
            "burst": 2000
        }),
    )
    .await;
    assert_eq!(limit["version"], 0);
    let limit_id = limit["data"]["id"].as_i64().unwrap();
    let deleted_limit = delete_empty_json(&app, &format!("/dynamic-rate-limits/{limit_id}")).await;
    assert_eq!(deleted_limit["version"], 0);

    let trusted = post_json(
        &app,
        "/trusted-cidrs",
        json!({"enabled": false, "cidr": "10.1.2.3/8", "comment": "disabled"}),
    )
    .await;
    assert_eq!(trusted["version"], 0);
    let changed_disabled_trusted = post_json(
        &app,
        "/trusted-cidrs",
        json!({"enabled": false, "cidr": "10.1.2.3/8", "comment": "still disabled"}),
    )
    .await;
    assert_eq!(changed_disabled_trusted["version"], 0);
    let deleted_trusted = delete_empty_json(&app, "/trusted-cidrs?cidr=10.1.2.3/8").await;
    assert_eq!(deleted_trusted["version"], 0);
}

#[tokio::test]
async fn geo_country_create_is_idempotent_for_same_policy() {
    let (app, db) = test_router().await;
    let body = json!({"country": "cn", "action": "deny", "enabled": true});

    let created_response = send_json(&app, Method::POST, "/geo-countries", body.clone()).await;
    assert_eq!(created_response.status(), StatusCode::CREATED);
    let created = response_json(created_response).await;
    assert_eq!(created["version"], 1);
    let first = load_geo_country_policy(&db, "CN", "deny", true).await;

    let unchanged_response = send_json(&app, Method::POST, "/geo-countries", body).await;
    assert_eq!(unchanged_response.status(), StatusCode::OK);
    let unchanged = response_json(unchanged_response).await;
    assert_eq!(unchanged["version"], 1);
    let second = load_geo_country_policy(&db, "CN", "deny", true).await;
    assert_eq!(second.updated_at, first.updated_at);
}
