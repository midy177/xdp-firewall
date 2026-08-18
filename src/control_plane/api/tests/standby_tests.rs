use super::*;
use crate::control_plane::api::routes::router;
use crate::control_plane::api::state::{ApiState, GeoRefreshLimiter, ThreatRefreshLimiter};
use crate::control_plane::xds;
use crate::db;
use crate::intelligence::geo;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

async fn standby_router() -> (Router, DatabaseConnection) {
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
        standby: true,
    });
    (app, db)
}

#[tokio::test]
async fn standby_rejects_writes_with_503_and_persists_nothing() {
    let (app, db) = standby_router().await;
    let response = send_json(
        &app,
        Method::POST,
        "/rules",
        json!({
            "priority": 10,
            "action": "deny",
            "cidr": "203.0.113.0/24",
            "protocol": "any"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        firewall_rule::Entity::find().all(&db).await.unwrap().len(),
        0,
        "no rule should be persisted in standby mode"
    );
}

#[tokio::test]
async fn standby_allows_get_reads() {
    let (app, _db) = standby_router().await;
    let response = send_empty(&app, Method::GET, "/rules").await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standby_health_returns_ok() {
    let (app, _db) = standby_router().await;
    let response = send_empty(&app, Method::GET, "/health").await;
    assert_eq!(response.status(), StatusCode::OK);
}
