use super::*;

#[tokio::test]
async fn batch_create_and_delete_support_config_resources() {
    let (app, _db) = test_router().await;

    let rules = create_batch_rules(&app).await;
    let countries = create_batch_countries(&app).await;
    let threats = create_batch_threat_sources(&app).await;
    let limits = create_batch_dynamic_rate_limits(&app).await;
    let bans = create_batch_temp_bans(&app).await;
    let trusted = create_batch_trusted_cidrs(&app).await;

    let delete_rules = delete_created_batch(&app, "/rules/batch", &rules).await;
    assert_eq!(delete_rules["version"], 7);
    assert_eq!(delete_rules["data"]["deleted"], 2);

    let delete_countries = delete_created_batch(&app, "/geo-countries/batch", &countries).await;
    assert_eq!(delete_countries["data"]["deleted"], 2);
    let delete_threats = delete_created_batch(&app, "/threat-sources/batch", &threats).await;
    assert_eq!(delete_threats["data"]["deleted"], 2);
    let delete_limits = delete_created_batch(&app, "/dynamic-rate-limits/batch", &limits).await;
    assert_eq!(delete_limits["data"]["deleted"], 2);
    let delete_bans = delete_created_batch(&app, "/temp-bans/batch", &bans).await;
    assert_eq!(delete_bans["data"]["deleted"], 2);
    let delete_trusted = delete_created_batch(&app, "/trusted-cidrs/batch", &trusted).await;
    assert_eq!(delete_trusted["version"], 12);
    assert_eq!(delete_trusted["data"]["deleted"], 2);

    let empty_batch_error =
        response_error(send_json(&app, Method::POST, "/rules/batch", json!({"items": []})).await)
            .await;
    assert!(empty_batch_error.contains("items must not be empty"));
}

async fn create_batch_rules(app: &Router) -> Value {
    let rules = post_json(
        app,
        "/rules/batch",
        json!({
            "items": [
                {"priority": 10, "action": "deny", "cidr": "203.0.113.1/24", "protocol": "tcp", "port": 443},
                {"priority": 20, "action": "allow", "cidr": "198.51.100.0/24", "protocol": "udp", "port": 53}
            ]
        }),
    )
    .await;
    assert_eq!(rules["version"], 1);
    assert_eq!(rules["data"].as_array().unwrap().len(), 2);
    assert_eq!(rules["data"][0]["cidr"], "203.0.113.0/24");
    rules
}

async fn create_batch_countries(app: &Router) -> Value {
    let countries = post_json(
        app,
        "/geo-countries/batch",
        json!({
            "items": [
                {"country": "cn", "action": "deny", "enabled": true},
                {"country": "us", "action": "allow", "enabled": false}
            ]
        }),
    )
    .await;
    assert_eq!(countries["version"], 2);
    assert_eq!(countries["data"].as_array().unwrap().len(), 2);
    assert_eq!(countries["data"][0]["country"], "CN");
    countries
}

async fn create_batch_threat_sources(app: &Router) -> Value {
    let threats = post_json(
        app,
        "/threat-sources/batch",
        json!({
            "items": [
                {
                    "name": "batch-feed-a",
                    "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                    "format": "cidr"
                },
                {
                    "enabled": false,
                    "name": "batch-feed-b",
                    "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
                    "format": "cidr",
                    "min_score": 1
                }
            ]
        }),
    )
    .await;
    assert_eq!(threats["version"], 3);
    assert_eq!(threats["data"].as_array().unwrap().len(), 2);
    threats
}

async fn create_batch_dynamic_rate_limits(app: &Router) -> Value {
    let limits = post_json(
        app,
        "/dynamic-rate-limits/batch",
        json!({
            "items": [
                {"enabled": true, "priority": 10, "protocol": "tcp", "port": 443, "packets_per_second": 1000, "burst": 2000},
                {"enabled": true, "priority": 20, "protocol": "any", "packets_per_second": 3000, "burst": 4000}
            ]
        }),
    )
    .await;
    assert_eq!(limits["version"], 4);
    assert_eq!(limits["data"].as_array().unwrap().len(), 2);
    limits
}

async fn create_batch_temp_bans(app: &Router) -> Value {
    let bans = post_json(
        app,
        "/temp-bans/batch",
        json!({
            "items": [
                {"cidr": "203.0.113.10/32", "protocol": "tcp", "port": 443, "duration_seconds": 300},
                {"cidr": "203.0.113.11/32", "protocol": "any", "duration_seconds": 600}
            ]
        }),
    )
    .await;
    assert_eq!(bans["version"], 5);
    assert_eq!(bans["data"].as_array().unwrap().len(), 2);
    bans
}

async fn create_batch_trusted_cidrs(app: &Router) -> Value {
    let trusted = post_json(
        app,
        "/trusted-cidrs/batch",
        json!({
            "items": [
                {"cidr": "10.1.2.3/8", "enabled": true},
                {"cidr": "192.0.2.10/24", "enabled": false, "comment": "batch"}
            ]
        }),
    )
    .await;
    assert_eq!(trusted["version"], 6);
    assert_eq!(trusted["data"].as_array().unwrap().len(), 2);
    assert_eq!(trusted["data"][0]["cidr"], "10.0.0.0/8");
    trusted
}

async fn delete_created_batch(app: &Router, uri: &str, created: &Value) -> Value {
    delete_json(
        app,
        uri,
        json!({"ids": [created["data"][0]["id"].clone(), created["data"][1]["id"].clone()]}),
    )
    .await
}
