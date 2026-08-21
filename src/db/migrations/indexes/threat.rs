use crate::db::entities;
use anyhow::Result;
use sea_orm::DatabaseConnection;
use sea_orm::sea_query::Index;

use super::schema::create_index;

pub(in crate::db::migrations) async fn create_threat_indexes(
    db: &DatabaseConnection,
) -> Result<()> {
    create_index(
        db,
        entities::threat_source::Entity,
        "idx_firewall_threat_sources_policy_name_name",
        Index::create()
            .col(entities::threat_source::Column::PolicyName)
            .col(entities::threat_source::Column::Name)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        entities::threat_source_state::Entity,
        "idx_firewall_threat_source_states_policy_name_source",
        Index::create()
            .col(entities::threat_source_state::Column::PolicyName)
            .col(entities::threat_source_state::Column::SourceName)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        entities::threat_prefix::Entity,
        "idx_firewall_threat_prefixes_policy_name_source",
        Index::create()
            .col(entities::threat_prefix::Column::PolicyName)
            .col(entities::threat_prefix::Column::SourceName)
            .unique()
            .to_owned(),
    )
    .await?;
    Ok(())
}
