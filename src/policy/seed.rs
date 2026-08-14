use crate::cli::ShowPolicyArgs;
use crate::db::entities::policy_version;
use crate::policy::{firewall, model::DEFAULT_POLICY_NAME};
use anyhow::Result;
use sea_orm::{DatabaseConnection, EntityTrait, TransactionTrait};
use tracing::info;

mod dynamic;
mod example;
#[cfg(test)]
mod tests;
mod threat_sources;
mod trusted_cidrs;

#[cfg(test)]
use dynamic::default_dynamic_defense_active_model;
use dynamic::insert_default_dynamic_defense;
pub use example::seed_example_policy;
use threat_sources::insert_builtin_threat_sources;
pub use trusted_cidrs::ensure_configured_trusted_cidrs;

pub async fn ensure_builtin_policy(db: &DatabaseConnection, policy_name: &str) -> Result<()> {
    let txn = db.begin().await?;
    if policy_version::Entity::find_by_id(policy_name.to_string())
        .one(&txn)
        .await?
        .is_some()
    {
        let inserted = insert_builtin_threat_sources(&txn, policy_name).await?;
        if inserted > 0 {
            let version = crate::db::next_policy_version_in_transaction(&txn, policy_name).await?;
            txn.commit().await?;
            info!(
                policy = %policy_name,
                version,
                inserted_builtin_threat_sources = inserted,
                "added missing built-in threat intelligence sources"
            );
        } else {
            txn.rollback().await?;
        }
        return Ok(());
    }

    insert_default_dynamic_defense(&txn, policy_name).await?;
    let inserted = insert_builtin_threat_sources(&txn, policy_name).await?;
    let version = crate::db::next_policy_version_in_transaction(&txn, policy_name).await?;
    txn.commit().await?;
    info!(
        policy = %policy_name,
        version,
        inserted_builtin_threat_sources = inserted,
        "initialized policy with built-in threat intelligence"
    );
    Ok(())
}

pub async fn show_policy(db: &DatabaseConnection, args: ShowPolicyArgs) -> Result<()> {
    let _ = args;
    let snapshot = firewall::load_policy(db, DEFAULT_POLICY_NAME).await?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}
