use super::runtime_cidrs::{
    RuntimeTrustedCidrSnapshot, RuntimeTrustedCidrs, cidr_fingerprint, compact_covered_cidrs,
    compact_runtime_trusted_cidrs_with_snapshot,
};
use super::*;
use crate::control_plane::xds::proto::{FetchGeoPrefixesRequest, firewall_xds_server::FirewallXds};
use crate::db::entities::{geo_country_policy, geo_ip_prefix, temp_ban};
use crate::policy::model::{
    DEFAULT_POLICY_NAME, DynamicDefensePolicy, PolicySnapshot, TrustedCidrPolicy,
};
use ipnet::IpNet;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DbBackend, EntityTrait, Set,
};
use tonic::Request;

#[test]
fn constant_time_eq_matches_equal_tokens() {
    assert!(auth::constant_time_eq("agent-token", "agent-token"));
    assert!(!auth::constant_time_eq("agent-token", "agent-tokem"));
    assert!(!auth::constant_time_eq("agent-token", "agent-token-extra"));
}

#[test]
fn policy_update_error_classifies_invalid_policy_as_data_error() {
    let error = PolicyUpdateError::InvalidPolicyJson(anyhow::anyhow!("invalid json"));

    assert!(!error.is_control_plane_failure());
}

#[test]
fn policy_update_error_classifies_tonic_status_as_control_plane_failure() {
    let error = PolicyUpdateError::ExternalGeoPrefixes(anyhow::Error::new(Status::unavailable(
        "control plane unavailable",
    )));

    assert!(error.is_control_plane_failure());
}

#[test]
fn drop_event_hub_tracks_all_and_node_scoped_subscriptions() {
    let hub = DropEventHub::new();
    assert!(!hub.enabled_for_node("node-a"));

    let node_subscription = hub.subscribe(Some("node-a".to_string()));
    assert!(hub.enabled_for_node("node-a"));
    assert!(!hub.enabled_for_node("node-b"));

    let all_subscription = hub.subscribe(None);
    assert!(hub.enabled_for_node("node-b"));

    drop(node_subscription);
    assert!(hub.enabled_for_node("node-a"));
    assert!(hub.enabled_for_node("node-b"));

    drop(all_subscription);
    assert!(!hub.enabled_for_node("node-a"));
    assert!(!hub.enabled_for_node("node-b"));
}

#[test]
fn compact_covered_cidrs_removes_only_contained_prefixes() {
    let compacted = compact_covered_cidrs(&[
        "172.30.133.54/32".parse().unwrap(),
        "172.30.0.0/16".parse().unwrap(),
        "10.0.0.0/24".parse().unwrap(),
        "10.0.1.0/24".parse().unwrap(),
        "fd00::1/128".parse().unwrap(),
        "fd00::/64".parse().unwrap(),
    ]);

    assert_eq!(compacted.covered, 2);
    assert_eq!(
        compacted.cidrs,
        vec![
            "172.30.0.0/16".parse::<IpNet>().unwrap(),
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
            "fd00::/64".parse().unwrap(),
        ]
    );
}

#[test]
fn runtime_compaction_uses_snapshot_trusted_cidrs() {
    let snapshot = PolicySnapshot {
        policy_name: DEFAULT_POLICY_NAME.to_string(),
        version: 1,
        rules: Vec::new(),
        geo_countries: Vec::new(),
        geo_prefixes: Vec::new(),
        temp_bans: Vec::new(),
        dynamic_defense: DynamicDefensePolicy::default(),
        dynamic_rate_limits: Vec::new(),
        trusted_cidrs: vec![TrustedCidrPolicy {
            cidr: "172.30.0.0/16".parse().unwrap(),
            comment: None,
        }],
        threat_sources: Vec::new(),
        threat_prefixes: Vec::new(),
    };
    let runtime = RuntimeTrustedCidrSnapshot {
        configured: vec!["172.30.133.54/32".parse().unwrap()],
        all: vec![
            "172.30.133.54/32".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
        ],
        inject: vec![
            "172.30.133.54/32".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
        ],
        covered: 0,
    };

    let compacted = compact_runtime_trusted_cidrs_with_snapshot(&snapshot, runtime);

    assert_eq!(
        compacted.all,
        vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]
    );
    assert_eq!(compacted.inject, compacted.all);
    assert_eq!(compacted.covered, 1);
}

#[tokio::test]
async fn temp_ban_cleanup_deletes_expired_rows_and_bumps_version() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    let now = chrono::Utc::now().naive_utc();
    temp_ban::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        cidr: Set("203.0.113.10/32".to_string()),
        protocol: Set("any".to_string()),
        port: Set(None),
        expires_at: Set(now - chrono::Duration::seconds(1)),
        comment: Set(Some("expired".to_string())),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    temp_ban::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        cidr: Set("203.0.113.20/32".to_string()),
        protocol: Set("tcp".to_string()),
        port: Set(Some(443)),
        expires_at: Set(now + chrono::Duration::seconds(300)),
        comment: Set(Some("active".to_string())),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let cleanup = TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL);
    cleanup.maybe_run(&db).await.unwrap();

    let rows = temp_ban::Entity::find().all(&db).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cidr, "203.0.113.20/32");
    assert_eq!(latest_version(&db).await.unwrap(), 1);

    temp_ban::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        cidr: Set("203.0.113.30/32".to_string()),
        protocol: Set("udp".to_string()),
        port: Set(Some(53)),
        expires_at: Set(now - chrono::Duration::seconds(1)),
        comment: Set(Some("expired inside throttle window".to_string())),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    cleanup.maybe_run(&db).await.unwrap();
    let rows = temp_ban::Entity::find().all(&db).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(latest_version(&db).await.unwrap(), 1);
}

#[tokio::test]
async fn build_policy_update_skips_policy_load_when_runtime_fingerprint_is_unchanged() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let version = latest_version(&db).await.unwrap();
    let runtime_trusted_cidrs =
        RuntimeTrustedCidrs::new(vec!["198.51.100.10/32".parse().unwrap()], None);
    let runtime_fingerprint = cidr_fingerprint(&runtime_trusted_cidrs.current_snapshot().await.all);
    db.execute_raw(crate::db::raw_sql(
        DbBackend::Sqlite,
        "DROP TABLE firewall_rules",
    ))
    .await
    .unwrap();

    let update = build_policy_update(
        &db,
        version,
        Some(runtime_fingerprint.as_str()),
        &runtime_trusted_cidrs,
        &TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL),
        false,
    )
    .await
    .unwrap();

    assert!(update.is_none());
}

fn test_service(db: DatabaseConnection) -> XdsService {
    XdsService {
        db,
        agent_token: None,
        push_interval: Duration::from_secs(1),
        drop_events: DropEventHub::new(),
        runtime_trusted_cidrs: RuntimeTrustedCidrs::new(Vec::new(), None),
        temp_ban_cleanup: TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL),
        geo_lookup: geo::GeoIpLookup::default(),
        threat_lookup: threat::ThreatIntelLookup::default(),
    }
}

async fn seed_enabled_country_with_prefixes(db: &DatabaseConnection) {
    let now = chrono::Utc::now().naive_utc();
    geo_country_policy::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(true),
        country: Set("US".to_string()),
        action: Set("deny".to_string()),
        packets_per_second: Set(None),
        burst: Set(None),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    geo_ip_prefix::ActiveModel {
        country: Set("US".to_string()),
        cidrs_json: Set(r#"["203.0.113.0/24","203.0.114.0/24"]"#.to_string()),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    crate::db::next_policy_version(db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
}

#[tokio::test]
async fn fetch_geo_prefixes_rejects_stale_version() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    seed_enabled_country_with_prefixes(&db).await;
    let version = latest_version(&db).await.unwrap();

    let service = test_service(db);

    // Matching version returns the persisted prefixes.
    let ok = service
        .fetch_geo_prefixes(Request::new(FetchGeoPrefixesRequest {
            version,
            page_size: 0,
            page_token: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.version, version);
    assert_eq!(ok.prefixes.len(), 2);
    assert!(ok.next_page_token.is_empty());

    // A stale version is rejected so the agent refetches the policy instead
    // of mixing a new policy with an old GeoIP snapshot.
    let stale = service
        .fetch_geo_prefixes(Request::new(FetchGeoPrefixesRequest {
            version: version + 1,
            page_size: 0,
            page_token: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
}
