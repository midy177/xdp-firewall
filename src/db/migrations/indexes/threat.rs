use crate::db::entities;
use anyhow::Result;
use sea_orm::sea_query::Index;
use sea_orm::{DatabaseConnection, EntityName};

use super::schema::create_index;

pub(in crate::db::migrations) async fn create_threat_indexes(
    db: &DatabaseConnection,
) -> Result<()> {
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_threat_sources_policy_name_name")
            .table(entities::threat_source::Entity.table_ref())
            .col(entities::threat_source::Column::PolicyName)
            .col(entities::threat_source::Column::Name)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_threat_source_states_policy_name_source")
            .table(entities::threat_source_state::Entity.table_ref())
            .col(entities::threat_source_state::Column::PolicyName)
            .col(entities::threat_source_state::Column::SourceName)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_threat_prefixes_policy_name_source")
            .table(entities::threat_prefix::Entity.table_ref())
            .col(entities::threat_prefix::Column::PolicyName)
            .col(entities::threat_prefix::Column::SourceName)
            .unique()
            .to_owned(),
    )
    .await?;
    Ok(())
}
