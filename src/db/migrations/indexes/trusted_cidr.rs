use crate::db::entities;
use anyhow::Result;
use sea_orm::sea_query::Index;
use sea_orm::{DatabaseConnection, EntityName};

use super::schema::create_index;

pub(in crate::db::migrations) async fn create_trusted_cidr_indexes(
    db: &DatabaseConnection,
) -> Result<()> {
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_trusted_cidrs_policy_name_cidr")
            .table(entities::trusted_cidr::Entity.table_ref())
            .col(entities::trusted_cidr::Column::PolicyName)
            .col(entities::trusted_cidr::Column::Cidr)
            .unique()
            .to_owned(),
    )
    .await?;
    Ok(())
}
