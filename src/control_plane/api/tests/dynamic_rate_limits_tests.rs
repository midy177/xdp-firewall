use super::*;

#[tokio::test]
async fn dynamic_rate_limit_create_persists_lists_and_loads_policy() {
    let (app, db) = test_router().await;
    let first = json!({
        "enabled": true,
        "priority": 20,
        "protocol": "tcp",
        "port": 443,
        "packets_per_second": 1000,
        "burst": 2000,
        "comment": "https custom limit"
    });
    let second = json!({
        "enabled": true,
        "priority": 10,
        "protocol": "udp",
        "packets_per_second": 3000,
        "burst": 4000,
        "comment": "udp custom limit"
    });

    let created_first =
        response_json(send_json(&app, Method::POST, "/dynamic-rate-limits", first).await).await;
    assert_eq!(created_first["version"], 1);
    assert_eq!(created_first["data"]["protocol"], "tcp");
    assert_eq!(created_first["data"]["port"], 443);

    let created_second =
        response_json(send_json(&app, Method::POST, "/dynamic-rate-limits", second).await).await;
    assert_eq!(created_second["version"], 2);
    assert_eq!(created_second["data"]["protocol"], "udp");
    assert!(created_second["data"]["port"].is_null());

    let page = response_json(
        send_empty(&app, Method::GET, "/dynamic-rate-limits?page=1&page_size=1").await,
    )
    .await;
    assert_eq!(page["total"], 2);
    assert_eq!(page["page"], 1);
    assert_eq!(page["page_size"], 1);
    assert_eq!(page["total_pages"], 2);
    assert_eq!(page["items"][0]["priority"], 10);
    assert_eq!(page["items"][0]["protocol"], "udp");

    let snapshot = firewall::load_policy(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
    assert_eq!(snapshot.version, 2);
    assert_eq!(snapshot.dynamic_rate_limits.len(), 2);
    assert_eq!(snapshot.dynamic_rate_limits[0].priority, 10);
    assert_eq!(snapshot.dynamic_rate_limits[0].protocol, L4Protocol::Udp);
    assert_eq!(snapshot.dynamic_rate_limits[0].port, None);
    assert_eq!(snapshot.dynamic_rate_limits[1].priority, 20);
    assert_eq!(snapshot.dynamic_rate_limits[1].protocol, L4Protocol::Tcp);
    assert_eq!(snapshot.dynamic_rate_limits[1].port, Some(443));
}

#[tokio::test]
async fn dynamic_rate_limit_create_is_idempotent_for_same_limit() {
    let (app, db) = test_router().await;
    let body = json!({
        "enabled": true,
        "priority": 10,
        "protocol": "tcp",
        "port": 443,
        "packets_per_second": 1000,
        "burst": 2000,
        "comment": "api"
    });

    let created_response =
        send_json(&app, Method::POST, "/dynamic-rate-limits", body.clone()).await;
    assert_eq!(created_response.status(), StatusCode::CREATED);
    let created = response_json(created_response).await;
    assert_eq!(created["version"], 1);
    let id = i32::try_from(created["data"]["id"].as_i64().unwrap()).unwrap();
    let first = load_dynamic_rate_limit(&db, id).await;

    let unchanged_response = send_json(&app, Method::POST, "/dynamic-rate-limits", body).await;
    assert_eq!(unchanged_response.status(), StatusCode::OK);
    let unchanged = response_json(unchanged_response).await;
    assert_eq!(unchanged["version"], 1);
    let second = load_dynamic_rate_limit(&db, id).await;
    assert_eq!(second.updated_at, first.updated_at);
}

#[tokio::test]
async fn dynamic_rate_limit_allows_port_only_limit_and_rejects_icmp_port() {
    let (app, _db) = test_router().await;
    let created = response_json(
        send_json(
            &app,
            Method::POST,
            "/dynamic-rate-limits",
            json!({
                "enabled": true,
                "priority": 10,
                "protocol": "any",
                "port": 443,
                "packets_per_second": 1000,
                "burst": 2000
            }),
        )
        .await,
    )
    .await;
    assert_eq!(created["data"]["protocol"], "any");
    assert_eq!(created["data"]["port"], 443);

    let error = response_error(
        send_json(
            &app,
            Method::POST,
            "/dynamic-rate-limits",
            json!({
                "enabled": true,
                "priority": 10,
                "protocol": "icmp",
                "port": 443,
                "packets_per_second": 1000,
                "burst": 2000
            }),
        )
        .await,
    )
    .await;
    assert!(error.contains("icmp dynamic rate limits cannot set a port"));
}
