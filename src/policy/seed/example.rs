use super::{
    dynamic::ensure_default_dynamic_defense_exists, threat_sources::insert_builtin_threat_sources,
};
use crate::{
    cli::SeedExampleArgs,
    db::entities::{
        firewall_rule, geo_country_policy, threat_prefix, threat_source, threat_source_state,
    },
    policy::model::DEFAULT_POLICY_NAME,
};
use anyhow::Result;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set, TransactionTrait,
};

pub async fn seed_example_policy(db: &DatabaseConnection, args: SeedExampleArgs) -> Result<()> {
    let _ = args;
    let policy_name = DEFAULT_POLICY_NAME;
    let txn = db.begin().await?;
    clear_example_policy_data(&txn, policy_name).await?;
    let now = chrono::Utc::now().naive_utc();
    insert_example_firewall_rules(&txn, policy_name, now).await?;
    insert_example_geo_country_policy(&txn, policy_name, now).await?;
    ensure_default_dynamic_defense_exists(&txn, policy_name, now).await?;
    insert_builtin_threat_sources(&txn, policy_name).await?;
    let version = crate::db::next_policy_version_in_transaction(&txn, policy_name).await?;
    txn.commit().await?;
    println!("seeded firewall policy at version {version}");
    Ok(())
}

async fn clear_example_policy_data(db: &impl ConnectionTrait, policy_name: &str) -> Result<()> {
    firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    threat_source_state::Entity::delete_many()
        .filter(threat_source_state::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    threat_prefix::Entity::delete_many()
        .filter(threat_prefix::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    Ok(())
}

async fn insert_example_firewall_rules(
    db: &impl ConnectionTrait,
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    firewall_rule::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        rule_key: Set(firewall_rule::generated_rule_key(
            10,
            "deny",
            "203.0.113.0/24",
            None,
            None,
        )),
        enabled: Set(true),
        priority: Set(10),
        action: Set("deny".to_string()),
        cidr: Set("203.0.113.0/24".to_string()),
        protocol: Set(None),
        port: Set(None),
        comment: Set(Some("example deny CIDR".to_string())),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    firewall_rule::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        rule_key: Set(firewall_rule::generated_rule_key(
            20,
            "allow",
            "10.0.0.0/8",
            None,
            None,
        )),
        enabled: Set(true),
        priority: Set(20),
        action: Set("allow".to_string()),
        cidr: Set("10.0.0.0/8".to_string()),
        protocol: Set(None),
        port: Set(None),
        comment: Set(Some("example private allow CIDR".to_string())),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}

async fn insert_example_geo_country_policy(
    db: &impl ConnectionTrait,
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    geo_country_policy::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        enabled: Set(true),
        country: Set("CN".to_string()),
        action: Set("allow".to_string()),
        packets_per_second: Set(None),
        burst: Set(None),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}
