use super::*;

#[tokio::test]
async fn rule_create_normalizes_cidr_and_rejects_invalid_ports() {
    let (app, _db) = test_router().await;
    let created = response_json(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "deny",
                "cidr": " 203.0.113.42/24 ",
                "protocol": "tcp",
                "port": 443
            }),
        )
        .await,
    )
    .await;
    assert_eq!(created["data"]["cidr"], "203.0.113.0/24");

    let any_port_rule = response_json(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "deny",
                "cidr": "203.0.113.0/24",
                "protocol": "any",
                "port": 443
            }),
        )
        .await,
    )
    .await;
    assert_eq!(any_port_rule["data"]["protocol"], "any");
    assert_eq!(any_port_rule["data"]["port"], 443);

    let range_error = response_error(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "deny",
                "cidr": "203.0.113.0/24",
                "protocol": "tcp",
                "port": 65536
            }),
        )
        .await,
    )
    .await;
    assert!(range_error.contains("port must be between 1 and 65535"));
}

#[tokio::test]
async fn rule_key_is_generated_unique_and_deletable() {
    let (app, db) = test_router().await;
    let created = create_rule(
        &app,
        keyed_rule_body(
            "edge-web-deny",
            10,
            "deny",
            "203.0.113.0/24",
            "tcp",
            Some(443),
        ),
    )
    .await;
    assert_eq!(created["data"]["rule_key"], "edge-web-deny");

    let generated = create_rule(&app, rule_body(30, "deny", "192.0.2.0/24", "any", Some(80))).await;
    let generated_rule_key = assert_generated_rule_key(&generated["data"]["rule_key"]);
    let first_generated_row = load_firewall_rule(&db, generated_rule_key).await;
    assert_eq!(
        generated_rule_key,
        firewall_rule::generated_rule_key(30, "deny", "192.0.2.0/24", Some("any"), Some(80),)
    );

    let duplicate_error = create_rule_error(
        &app,
        keyed_rule_body(
            "edge-web-deny",
            20,
            "allow",
            "198.51.100.0/24",
            "udp",
            Some(53),
        ),
    )
    .await;
    assert!(duplicate_error.contains("rule_key already exists"));

    let generated_duplicate_response = send_json(
        &app,
        Method::POST,
        "/rules",
        rule_body(30, "deny", "192.0.2.0/24", "any", Some(80)),
    )
    .await;
    assert_eq!(generated_duplicate_response.status(), StatusCode::OK);
    let generated_duplicate = response_json(generated_duplicate_response).await;
    assert_eq!(generated_duplicate["version"], generated["version"]);
    let second_generated_row = load_firewall_rule(&db, generated_rule_key).await;
    assert_eq!(
        second_generated_row.updated_at,
        first_generated_row.updated_at
    );

    let page =
        response_json(send_empty(&app, Method::GET, "/rules?rule_key=edge-web-deny").await).await;
    assert_eq!(page["total"], 1);
    assert_eq!(page["items"][0]["rule_key"], "edge-web-deny");

    let deleted =
        response_json(send_empty(&app, Method::DELETE, "/rules?rule_key=edge-web-deny").await)
            .await;
    assert_eq!(deleted["data"]["deleted"], 1);
}

#[tokio::test]
async fn deny_rule_rejects_cidr_containing_node_interface_ip() {
    let (app, db) = test_router().await;
    insert_test_node(&db, "node-a", "10.0.0.10,2001:db8::10").await;

    let deny_error = response_error(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "deny",
                "cidr": "10.0.0.0/24",
                "protocol": "any"
            }),
        )
        .await,
    )
    .await;
    assert!(deny_error.contains("contains node node-a interface eth0 IP 10.0.0.10"));

    response_json(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "allow",
                "cidr": "10.0.0.0/24",
                "protocol": "any"
            }),
        )
        .await,
    )
    .await;
}

#[tokio::test]
async fn rule_batch_delete_supports_either_ids_or_rule_keys() {
    let (app, _db) = test_router().await;

    let by_id = create_rule(
        &app,
        keyed_rule_body(
            "batch-by-id",
            10,
            "deny",
            "203.0.113.0/24",
            "tcp",
            Some(443),
        ),
    )
    .await;
    let by_key = create_rule(
        &app,
        keyed_rule_body(
            "batch-by-key",
            20,
            "allow",
            "198.51.100.0/24",
            "udp",
            Some(53),
        ),
    )
    .await;

    let mixed_error = delete_rules_batch_error(
        &app,
        json!({
            "ids": [by_id["data"]["id"]],
            "rule_keys": ["batch-by-key"]
        }),
    )
    .await;
    assert!(mixed_error.contains("ids and rule_keys cannot be used together"));

    let deleted_by_id = delete_rules_batch(
        &app,
        json!({
            "ids": [by_id["data"]["id"]],
            "rule_keys": ["", " "]
        }),
    )
    .await;
    assert_eq!(deleted_by_id["data"]["deleted"], 1);

    let deleted_by_key = delete_rules_batch(
        &app,
        json!({
            "rule_keys": [by_key["data"]["rule_key"]]
        }),
    )
    .await;
    assert_eq!(deleted_by_key["data"]["deleted"], 1);

    let keep = create_rule(
        &app,
        keyed_rule_body("batch-keep", 30, "deny", "192.0.2.0/24", "any", Some(80)),
    )
    .await;

    let remaining = response_json(send_empty(&app, Method::GET, "/rules").await).await;
    assert_eq!(remaining["total"], 1);
    assert_eq!(remaining["items"][0]["id"], keep["data"]["id"]);
}

#[tokio::test]
async fn rule_query_and_delete_support_tuple_filters() {
    let (app, _db) = test_router().await;
    response_json(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "deny",
                "cidr": "203.0.113.42/24",
                "protocol": "tcp",
                "port": 443
            }),
        )
        .await,
    )
    .await;
    response_json(
        send_json(
            &app,
            Method::POST,
            "/rules",
            json!({
                "priority": 10,
                "action": "deny",
                "cidr": "203.0.113.0/24",
                "protocol": "tcp",
                "port": 80
            }),
        )
        .await,
    )
    .await;

    let page = response_json(
        send_empty(
            &app,
            Method::GET,
            "/rules?action=drop&cidr=203.0.113.99/24&protocol=tcp&port=443&priority=10",
        )
        .await,
    )
    .await;
    assert_eq!(page["total"], 1);
    assert_eq!(page["items"][0]["cidr"], "203.0.113.0/24");
    assert_eq!(page["items"][0]["port"], 443);

    let deleted = response_json(
        send_empty(
            &app,
            Method::DELETE,
            "/rules?action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10",
        )
        .await,
    )
    .await;
    assert_eq!(deleted["version"], 3);
    assert_eq!(deleted["data"]["deleted"], 1);

    let remaining = response_json(send_empty(&app, Method::GET, "/rules").await).await;
    assert_eq!(remaining["total"], 1);
    assert_eq!(remaining["items"][0]["port"], 80);
}
