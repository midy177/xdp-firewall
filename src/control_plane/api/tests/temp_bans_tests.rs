use super::*;

#[tokio::test]
async fn temporary_ban_accepts_cidr_source_and_rejects_bare_ip() {
    let (app, _db) = test_router().await;
    let bare_ip_error = response_error(
        send_json(
            &app,
            Method::POST,
            "/temp-bans",
            json!({
                "cidr": "203.0.113.10",
                "protocol": "tcp",
                "port": 443,
                "duration_seconds": 300
            }),
        )
        .await,
    )
    .await;
    assert!(bare_ip_error.contains("CIDR must include a prefix length"));

    let port_error = response_error(
        send_json(
            &app,
            Method::POST,
            "/temp-bans",
            json!({
                "cidr": "203.0.113.10/32",
                "protocol": "tcp",
                "port": 0,
                "duration_seconds": 300
            }),
        )
        .await,
    )
    .await;
    assert!(port_error.contains("port must be between 1 and 65535"));

    response_json(
        send_json(
            &app,
            Method::POST,
            "/temp-bans",
            json!({
                "cidr": "203.0.113.10/32",
                "protocol": "tcp",
                "port": 443,
                "duration_seconds": 300
            }),
        )
        .await,
    )
    .await;
    let filtered = response_json(
        send_empty(
            &app,
            Method::GET,
            "/temp-bans?cidr=203.0.113.10/32&protocol=tcp&port=443",
        )
        .await,
    )
    .await;
    assert_eq!(filtered["total"], 1);
}

#[tokio::test]
async fn temporary_ban_rejects_cidr_containing_node_interface_ip() {
    let (app, db) = test_router().await;
    insert_test_node(&db, "node-a", "10.0.0.10").await;

    let error = response_error(
        send_json(
            &app,
            Method::POST,
            "/temp-bans",
            json!({
                "cidr": "10.0.0.10/32",
                "protocol": "any",
                "duration_seconds": 300
            }),
        )
        .await,
    )
    .await;
    assert!(error.contains(
        "temporary ban CIDR 10.0.0.10/32 contains node node-a interface eth0 IP 10.0.0.10"
    ));
}
