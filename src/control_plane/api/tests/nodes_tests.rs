use super::*;

#[tokio::test]
async fn nodes_report_sync_health_and_maintenance_prunes_stale_rows() {
    let (app, db) = test_router().await;
    db::next_policy_version(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
    db::next_policy_version(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
    let now = chrono::Utc::now().naive_utc();

    node::Entity::insert_many([
        test_node_model("fresh-ok", "198.51.100.10", now, 2),
        test_node_model("fresh-stale", "198.51.100.11", now, 1),
        test_node_model(
            "old-ok",
            "198.51.100.12",
            now - chrono::Duration::seconds(600),
            2,
        ),
    ])
    .exec(&db)
    .await
    .unwrap();

    let page =
        response_json(send_empty(&app, Method::GET, "/nodes?page=1&page_size=10").await).await;
    assert_eq!(page["total"], 3);
    let items = page["items"].as_array().unwrap();
    let fresh_ok = find_json_item(items, "node_id", "fresh-ok");
    assert_eq!(fresh_ok["current_policy_version"], 2);
    assert_eq!(fresh_ok["sync_status"], "ok");
    assert_eq!(fresh_ok["healthy"], true);
    let fresh_stale = find_json_item(items, "node_id", "fresh-stale");
    assert_eq!(fresh_stale["sync_status"], "stale");
    assert_eq!(fresh_stale["healthy"], false);
    let old_ok = find_json_item(items, "node_id", "old-ok");
    assert_eq!(old_ok["sync_status"], "offline");
    assert_eq!(old_ok["healthy"], false);
    assert!(old_ok["seconds_since_seen"].as_i64().unwrap() >= 600);

    let pruned = response_json(
        send_empty(&app, Method::POST, "/nodes/maintenance?max_age_seconds=300").await,
    )
    .await;
    assert_eq!(pruned["deleted"], 1);
    assert_eq!(pruned["max_age_seconds"], 300);

    let page =
        response_json(send_empty(&app, Method::GET, "/nodes?page=1&page_size=10").await).await;
    assert_eq!(page["total"], 2);
}
