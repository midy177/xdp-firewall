use crate::db::entities;
use anyhow::Result;
use sea_orm::DatabaseConnection;
use sea_orm::sea_query::Index;

use super::schema::create_index;

pub(in crate::db::migrations) async fn create_dynamic_policy_indexes(
    db: &DatabaseConnection,
) -> Result<()> {
    create_index(
        db,
        entities::dynamic_rate_limit::Entity,
        "idx_firewall_dynamic_rate_limits_policy_name_priority",
        Index::create()
            .col(entities::dynamic_rate_limit::Column::PolicyName)
            .col(entities::dynamic_rate_limit::Column::Priority)
            .to_owned(),
    )
    .await?;
    Ok(())
}
