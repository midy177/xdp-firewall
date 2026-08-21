use crate::db::entities;
use anyhow::Result;
use sea_orm::DatabaseConnection;
use sea_orm::sea_query::Index;

use super::schema::create_index;

pub(in crate::db::migrations) async fn create_temp_ban_indexes(
    db: &DatabaseConnection,
) -> Result<()> {
    create_index(
        db,
        entities::temp_ban::Entity,
        "idx_firewall_temp_bans_policy_name_expires_at",
        Index::create()
            .col(entities::temp_ban::Column::PolicyName)
            .col(entities::temp_ban::Column::ExpiresAt)
            .to_owned(),
    )
    .await?;
    Ok(())
}
