use crate::db::entities;
use anyhow::Result;
use sea_orm::sea_query::Index;
use sea_orm::{DatabaseConnection, EntityName};

use super::schema::create_index;

pub(in crate::db::migrations) async fn create_geo_indexes(db: &DatabaseConnection) -> Result<()> {
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_geo_country_catalog_code")
            .table(entities::geo_country_catalog::Entity.table_ref())
            .col(entities::geo_country_catalog::Column::Code)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_geo_ip_list_states_country")
            .table(entities::geo_ip_list_state::Entity.table_ref())
            .col(entities::geo_ip_list_state::Column::Country)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_geo_ip_prefixes_country")
            .table(entities::geo_ip_prefix::Entity.table_ref())
            .col(entities::geo_ip_prefix::Column::Country)
            .unique()
            .to_owned(),
    )
    .await?;
    Ok(())
}
