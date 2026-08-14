use super::*;
use crate::{
    cli::SeedExampleArgs,
    db::entities::{
        dynamic_defense, firewall_rule, geo_country_policy, policy_version, threat_source,
    },
    intelligence::threat,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, EntityTrait, QueryFilter, Set,
};

#[test]
fn normalizes_trusted_cidrs_from_repeated_and_comma_values() {
    let cidrs = trusted_cidrs::normalize_trusted_cidrs(&[
        "10.1.2.3/8".to_string(),
        "192.168.0.0/16,10.0.0.0/8".to_string(),
    ])
    .unwrap();

    assert_eq!(cidrs, vec!["10.0.0.0/8", "192.168.0.0/16"]);
}

#[tokio::test]
async fn ensure_builtin_policy_adds_missing_builtin_sources_for_existing_policy() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let now = chrono::Utc::now().naive_utc();

    policy_version::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        version: Set(7),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    for source in &threat::BUILTIN_THREAT_SOURCES[..2] {
        threat_source::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(true),
            name: Set(source.name.to_string()),
            url: Set(source.url.to_string()),
            format: Set(source.format.to_string()),
            min_score: Set(source.min_score),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
    }

    ensure_builtin_policy(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();

    let sources = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(sources.len(), threat::BUILTIN_THREAT_SOURCES.len());
    assert!(sources.iter().any(|source| source.name == "voipbl"));

    let version = policy_version::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .version;
    assert_eq!(version, 8);

    ensure_builtin_policy(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
    let version = policy_version::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .version;
    assert_eq!(version, 8);
}

#[tokio::test]
async fn ensure_builtin_policy_preserves_existing_dynamic_defense_updated_at() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let existing_updated_at = chrono::DateTime::from_timestamp(1_700_000_000, 0)
        .unwrap()
        .naive_utc();

    default_dynamic_defense_active_model(DEFAULT_POLICY_NAME, existing_updated_at)
        .unwrap()
        .insert(&db)
        .await
        .unwrap();

    ensure_builtin_policy(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();

    let row = dynamic_defense::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.updated_at, existing_updated_at);
}

#[tokio::test]
async fn seed_example_policy_rolls_back_when_reseed_fails() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let now = chrono::Utc::now().naive_utc();
    let duplicate_rule_key =
        firewall_rule::generated_rule_key(10, "deny", "203.0.113.0/24", None, None);

    firewall_rule::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        rule_key: Set("old-default-rule".to_string()),
        enabled: Set(true),
        priority: Set(99),
        action: Set("allow".to_string()),
        cidr: Set("198.51.100.0/24".to_string()),
        protocol: Set(None),
        port: Set(None),
        comment: Set(Some("must survive failed reseed".to_string())),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
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
    policy_version::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        version: Set(7),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();
    firewall_rule::ActiveModel {
        policy_name: Set("other-policy".to_string()),
        rule_key: Set(duplicate_rule_key),
        enabled: Set(true),
        priority: Set(10),
        action: Set("deny".to_string()),
        cidr: Set("203.0.113.0/24".to_string()),
        protocol: Set(None),
        port: Set(None),
        comment: Set(Some("forces unique rule_key failure".to_string())),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let result = seed_example_policy(&db, SeedExampleArgs {}).await;

    assert!(result.is_err());
    let rules = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_key, "old-default-rule");
    let countries = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(countries.len(), 1);
    assert_eq!(countries[0].country, "US");
    let version = policy_version::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .version;
    assert_eq!(version, 7);
}
