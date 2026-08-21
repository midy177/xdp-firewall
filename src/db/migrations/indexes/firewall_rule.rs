use crate::db::entities;
use anyhow::Result;
use sea_orm::DatabaseConnection;
use sea_orm::sea_query::Index;

use super::schema::{create_index, drop_index_if_exists};

pub(in crate::db::migrations) async fn ensure_firewall_rule_key_unique_index(
    db: &DatabaseConnection,
) -> Result<()> {
    drop_index_if_exists(
        db,
        "idx_firewall_rules_policy_name_rule_key",
        "firewall_rules",
    )
    .await?;
    create_index(
        db,
        entities::firewall_rule::Entity,
        "idx_firewall_rules_rule_key",
        Index::create()
            .col(entities::firewall_rule::Column::RuleKey)
            .unique()
            .to_owned(),
    )
    .await?;
    Ok(())
}
