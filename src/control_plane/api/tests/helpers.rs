use crate::{
    control_plane::{
        api::{
            routes::router,
            state::{ApiState, GeoRefreshLimiter, ThreatRefreshLimiter},
        },
        xds,
    },
    db::{
        self,
        entities::{
            dynamic_rate_limit, firewall_rule, geo_country_policy, node, threat_prefix,
            threat_source, threat_source_state, trusted_cidr,
        },
    },
    intelligence::geo,
    policy::model::DEFAULT_POLICY_NAME,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
    response::Response,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, Set,
};
use serde_json::{Value, json};
use tower::ServiceExt;

pub(super) async fn test_router() -> (Router, DatabaseConnection) {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.max_connections(1);
    let db = Database::connect(options).await.unwrap();
    db::migrate(&db).await.unwrap();
    let app = router(ApiState {
        db: db.clone(),
        api_token: None,
        drop_events: xds::DropEventHub::new(),
        geo_lookup: geo::GeoIpLookup::default(),
        geo_refresh_limiter: GeoRefreshLimiter::default(),
        threat_refresh_limiter: ThreatRefreshLimiter::default(),
    });
    (app, db)
}

pub(super) async fn insert_test_node(db: &DatabaseConnection, node_id: &str, interface_ips: &str) {
    test_node_model(node_id, interface_ips, chrono::Utc::now().naive_utc(), 1)
        .insert(db)
        .await
        .unwrap();
}

pub(super) fn test_node_model(
    node_id: &str,
    interface_ips: &str,
    last_seen_at: chrono::NaiveDateTime,
    last_applied_version: i64,
) -> node::ActiveModel {
    node::ActiveModel {
        node_id: Set(node_id.to_string()),
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        interface_name: Set("eth0".to_string()),
        interface_ips: Set(interface_ips.to_string()),
        last_seen_at: Set(last_seen_at),
        last_applied_version: Set(last_applied_version),
        status: Set("ok".to_string()),
        error: Set(None),
    }
}

pub(super) fn find_json_item<'a>(items: &'a [Value], field: &str, expected: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item[field] == expected)
        .unwrap_or_else(|| panic!("missing item with {field}={expected}"))
}

pub(super) fn assert_generated_rule_key(value: &Value) -> &str {
    let rule_key = value.as_str().expect("rule_key must be a string");
    assert_eq!(rule_key.len(), 36);
    for index in [8, 13, 18, 23] {
        assert_eq!(rule_key.as_bytes()[index], b'-');
    }
    assert!(
        rule_key
            .bytes()
            .enumerate()
            .all(|(index, byte)| { matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit() })
    );
    rule_key
}

pub(super) async fn send_json(app: &Router, method: Method, uri: &str, body: Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn send_empty(app: &Router, method: Method, uri: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn response_json(response: Response) -> Value {
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(
        status.is_success(),
        "expected success response, got {status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

pub(super) async fn response_error(response: Response) -> String {
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(
        !status.is_success(),
        "expected error response, got {status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice::<Value>(&body).unwrap()["error"]
        .as_str()
        .unwrap()
        .to_string()
}

pub(super) async fn get_json(app: &Router, uri: &str) -> Value {
    response_json(send_empty(app, Method::GET, uri).await).await
}

pub(super) async fn post_json(app: &Router, uri: &str, body: Value) -> Value {
    response_json(send_json(app, Method::POST, uri, body).await).await
}

pub(super) async fn create_rule(app: &Router, body: Value) -> Value {
    post_json(app, "/rules", body).await
}

pub(super) async fn create_rule_error(app: &Router, body: Value) -> String {
    response_error(send_json(app, Method::POST, "/rules", body).await).await
}

pub(super) async fn delete_rules_batch(app: &Router, body: Value) -> Value {
    response_json(send_json(app, Method::DELETE, "/rules/batch", body).await).await
}

pub(super) async fn delete_rules_batch_error(app: &Router, body: Value) -> String {
    response_error(send_json(app, Method::DELETE, "/rules/batch", body).await).await
}

pub(super) fn rule_body(
    priority: i64,
    action: &str,
    cidr: &str,
    protocol: &str,
    port: Option<i64>,
) -> Value {
    let mut body = json!({
        "priority": priority,
        "action": action,
        "cidr": cidr,
        "protocol": protocol
    });
    if let Some(port) = port {
        body["port"] = json!(port);
    }
    body
}

pub(super) fn keyed_rule_body(
    rule_key: &str,
    priority: i64,
    action: &str,
    cidr: &str,
    protocol: &str,
    port: Option<i64>,
) -> Value {
    let mut body = rule_body(priority, action, cidr, protocol, port);
    body["rule_key"] = json!(rule_key);
    body
}

pub(super) async fn delete_json(app: &Router, uri: &str, body: Value) -> Value {
    response_json(send_json(app, Method::DELETE, uri, body).await).await
}

pub(super) async fn delete_empty_json(app: &Router, uri: &str) -> Value {
    response_json(send_empty(app, Method::DELETE, uri).await).await
}

pub(super) async fn create_test_config_resources(app: &Router) {
    post_json(
        app,
        "/geo-countries",
        json!({"country": "cn", "action": "deny", "enabled": true}),
    )
    .await;
    post_json(
        app,
        "/threat-sources",
        json!({
            "name": "test-feed",
            "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            "format": "cidr"
        }),
    )
    .await;
    post_json(
        app,
        "/dynamic-rate-limits",
        json!({
            "enabled": true,
            "priority": 10,
            "protocol": "tcp",
            "port": 443,
            "packets_per_second": 1000,
            "burst": 2000
        }),
    )
    .await;
    post_json(
        app,
        "/trusted-cidrs",
        json!({"cidr": "10.1.2.3/8", "enabled": true}),
    )
    .await;
}

pub(super) async fn insert_test_threat_state(db: &DatabaseConnection, source_name: &str) {
    let now = chrono::Utc::now().naive_utc();
    threat_source_state::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set(source_name.to_string()),
        fingerprint: Set("test-fingerprint".to_string()),
        prefix_count: Set(1),
        last_checked_at: Set(now),
        last_changed_at: Set(Some(now)),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
}

pub(super) async fn load_trusted_cidr(db: &DatabaseConnection, cidr: &str) -> trusted_cidr::Model {
    trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(trusted_cidr::Column::Cidr.eq(cidr))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn load_firewall_rule(
    db: &DatabaseConnection,
    rule_key: &str,
) -> firewall_rule::Model {
    firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(firewall_rule::Column::RuleKey.eq(rule_key))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn load_geo_country_policy(
    db: &DatabaseConnection,
    country: &str,
    action: &str,
    enabled: bool,
) -> geo_country_policy::Model {
    geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Country.eq(country))
        .filter(geo_country_policy::Column::Action.eq(action))
        .filter(geo_country_policy::Column::Enabled.eq(enabled))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn load_dynamic_rate_limit(
    db: &DatabaseConnection,
    id: i32,
) -> dynamic_rate_limit::Model {
    dynamic_rate_limit::Entity::find_by_id(id)
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn load_threat_source(
    db: &DatabaseConnection,
    name: &str,
) -> threat_source::Model {
    threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Name.eq(name))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn create_test_threat_source(app: &Router, name: &str, enabled: bool) -> i32 {
    let created = post_json(
        app,
        "/threat-sources",
        json!({
            "enabled": enabled,
            "name": name,
            "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            "format": "cidr"
        }),
    )
    .await;
    i32::try_from(created["data"]["id"].as_i64().unwrap()).unwrap()
}

pub(super) async fn set_threat_source_enabled(db: &DatabaseConnection, id: i32, enabled: bool) {
    let row = threat_source::Entity::find_by_id(id)
        .one(db)
        .await
        .unwrap()
        .unwrap();
    let mut active: threat_source::ActiveModel = row.into();
    active.enabled = Set(enabled);
    active.update(db).await.unwrap();
}

pub(super) async fn insert_test_threat_prefix(
    db: &DatabaseConnection,
    source_name: &str,
    cidrs_json: &str,
) {
    threat_prefix::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set(source_name.to_string()),
        cidrs_json: Set(cidrs_json.to_string()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
}

pub(super) async fn persisted_threat_state_count(db: &DatabaseConnection) -> u64 {
    threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .count(db)
        .await
        .unwrap()
}

pub(super) async fn persisted_threat_prefix_count(db: &DatabaseConnection) -> u64 {
    threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .count(db)
        .await
        .unwrap()
}
