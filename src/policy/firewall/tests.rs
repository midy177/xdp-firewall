use super::*;
use crate::db::entities::{geo_country_policy, geo_ip_prefix, threat_prefix, threat_source};
use crate::policy::compile::compile_policy;
use crate::policy::model::{DEFAULT_POLICY_NAME, RuleAction, XdpRuleSource};
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, Set};

#[tokio::test]
async fn load_policy_without_geo_prefixes_keeps_country_rules_but_skips_prefixes() {
    let db = sqlite_memory_db().await;
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
    .insert(&db)
    .await
    .unwrap();
    geo_ip_prefix::ActiveModel {
        country: Set("US".to_string()),
        cidrs_json: Set(r#"["203.0.113.0/24"]"#.to_string()),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let full = load_policy(&db, DEFAULT_POLICY_NAME).await.unwrap();
    assert_eq!(full.geo_countries.len(), 1);
    assert_eq!(full.geo_prefixes.len(), 1);

    let slim = load_policy_without_geo_prefixes(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
    assert_eq!(slim.geo_countries.len(), 1);
    assert!(slim.geo_prefixes.is_empty());
}

#[tokio::test]
async fn load_policy_uses_persisted_threat_prefixes() {
    let db = sqlite_memory_db().await;
    let now = chrono::Utc::now().naive_utc();

    threat_source::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(true),
        name: Set("test-feed".to_string()),
        url: Set("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt".to_string()),
        format: Set("ipsum".to_string()),
        min_score: Set(Some(3)),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    threat_prefix::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set("test-feed".to_string()),
        cidrs_json: Set(r#"["198.51.100.0/24","203.0.113.10/32"]"#.to_string()),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let snapshot = load_policy(&db, DEFAULT_POLICY_NAME).await.unwrap();
    assert_eq!(snapshot.threat_sources.len(), 1);
    assert_eq!(snapshot.threat_prefixes.len(), 2);

    let compiled = compile_policy(&snapshot).unwrap();
    assert_eq!(compiled.threat_prefixes.len(), 2);
    assert!(compiled.threat_prefixes.iter().all(|rule| {
        rule.action == RuleAction::Deny && rule.source == XdpRuleSource::ThreatIntel
    }));
}

async fn sqlite_memory_db() -> sea_orm::DatabaseConnection {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    db
}
