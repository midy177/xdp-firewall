use super::*;

#[tokio::test]
async fn threat_source_create_is_idempotent_for_same_source() {
    let (app, db) = test_router().await;
    let body = json!({
        "enabled": true,
        "name": "stable-feed",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "format": "ipsum",
        "min_score": 3
    });

    let created_response = send_json(&app, Method::POST, "/threat-sources", body.clone()).await;
    assert_eq!(created_response.status(), StatusCode::CREATED);
    let created = response_json(created_response).await;
    assert_eq!(created["version"], 1);
    let first = load_threat_source(&db, "stable-feed").await;

    let unchanged_response = send_json(&app, Method::POST, "/threat-sources", body).await;
    assert_eq!(unchanged_response.status(), StatusCode::OK);
    let unchanged = response_json(unchanged_response).await;
    assert_eq!(unchanged["version"], 1);
    let second = load_threat_source(&db, "stable-feed").await;
    assert_eq!(second.updated_at, first.updated_at);

    let conflict = response_error(
        send_json(
            &app,
            Method::POST,
            "/threat-sources",
            json!({
                "enabled": true,
                "name": "stable-feed",
                "url": "https://voipbl.org/update/",
                "format": "voipbl"
            }),
        )
        .await,
    )
    .await;
    assert!(conflict.contains("name already exists"));
}

#[tokio::test]
async fn disabled_threat_source_create_and_delete_do_not_bump_policy_version() {
    let (app, _db) = test_router().await;

    let created_response = send_json(
        &app,
        Method::POST,
        "/threat-sources",
        json!({
            "enabled": false,
            "name": "disabled-feed",
            "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            "format": "ipsum",
            "min_score": 3
        }),
    )
    .await;

    assert_eq!(created_response.status(), StatusCode::CREATED);
    let created = response_json(created_response).await;
    assert_eq!(created["version"], 0);

    let deleted = delete_empty_json(&app, "/threat-sources?name=disabled-feed").await;
    assert_eq!(deleted["version"], 0);
}

#[tokio::test]
async fn threat_source_batch_returns_ok_when_all_items_are_unchanged() {
    let (app, _db) = test_router().await;
    let body = json!({
        "items": [
            {
                "enabled": true,
                "name": "batch-stable-feed",
                "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                "format": "ipsum",
                "min_score": 3
            }
        ]
    });

    let created_response =
        send_json(&app, Method::POST, "/threat-sources/batch", body.clone()).await;
    assert_eq!(created_response.status(), StatusCode::CREATED);
    let created = response_json(created_response).await;
    assert_eq!(created["version"], 1);

    let unchanged_response = send_json(&app, Method::POST, "/threat-sources/batch", body).await;
    assert_eq!(unchanged_response.status(), StatusCode::OK);
    let unchanged = response_json(unchanged_response).await;
    assert_eq!(unchanged["version"], 1);
}

#[tokio::test]
async fn threat_source_update_toggles_enabled_and_cleans_persisted_data() {
    let (app, db) = test_router().await;
    let id = create_test_threat_source(&app, "toggle-feed", false).await;
    set_threat_source_enabled(&db, id, true).await;
    insert_test_threat_state(&db, "toggle-feed").await;
    insert_test_threat_prefix(&db, "toggle-feed", "[\"203.0.113.0/24\"]").await;

    let disabled = response_json(
        send_json(
            &app,
            Method::PUT,
            &format!("/threat-sources/{id}"),
            json!({"enabled": false}),
        )
        .await,
    )
    .await;
    assert_eq!(disabled["data"]["enabled"], false);
    assert_eq!(persisted_threat_state_count(&db).await, 0);
    assert_eq!(persisted_threat_prefix_count(&db).await, 0);
    let disabled_query =
        response_json(send_empty(&app, Method::GET, "/threat-sources?enabled=false").await).await;
    assert_eq!(disabled_query["total"], 1);

    let enabled = response_json(
        send_json(
            &app,
            Method::PUT,
            &format!("/threat-sources/{id}"),
            json!({"enabled": true}),
        )
        .await,
    )
    .await;
    assert_eq!(enabled["data"]["enabled"], true);
}

#[tokio::test]
async fn threat_source_refresh_endpoint_debounces_manual_refreshes() {
    let (app, _db) = test_router().await;

    let first =
        response_json(send_empty(&app, Method::POST, "/threat-sources/refresh").await).await;
    assert_eq!(first["data"]["refresh_status"], "running");
    assert_eq!(first["data"]["running"], true);

    let second =
        response_json(send_empty(&app, Method::POST, "/threat-sources/refresh").await).await;
    assert_eq!(second["data"]["refresh_status"], "running");
    assert_eq!(second["data"]["running"], true);
}
