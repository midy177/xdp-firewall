use super::legacy;
use crate::db::entities;
use anyhow::Result;
use sea_orm::{ConnectionTrait, DatabaseConnection, Schema};

pub(super) async fn create_policy_tables(db: &DatabaseConnection, schema: &Schema) -> Result<()> {
    create_table(
        db,
        schema.create_table_from_entity(entities::policy_version::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::firewall_rule::Entity),
    )
    .await?;
    legacy::ensure_firewall_rule_key_column(db).await?;
    Ok(())
}

pub(super) async fn create_geo_tables(db: &DatabaseConnection, schema: &Schema) -> Result<()> {
    create_table(
        db,
        schema.create_table_from_entity(entities::geo_country_policy::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::geo_country_catalog::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::geo_ip_list_state::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::geo_ip_prefix::Entity),
    )
    .await?;
    Ok(())
}

pub(super) async fn create_threat_tables(db: &DatabaseConnection, schema: &Schema) -> Result<()> {
    create_table(
        db,
        schema.create_table_from_entity(entities::threat_source::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::threat_source_state::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::threat_prefix::Entity),
    )
    .await?;
    Ok(())
}

pub(super) async fn create_dynamic_policy_tables(
    db: &DatabaseConnection,
    schema: &Schema,
) -> Result<()> {
    create_table(
        db,
        schema.create_table_from_entity(entities::dynamic_defense::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::dynamic_rate_limit::Entity),
    )
    .await?;
    Ok(())
}

pub(super) async fn create_temp_ban_tables(db: &DatabaseConnection, schema: &Schema) -> Result<()> {
    create_table(
        db,
        schema.create_table_from_entity(entities::temp_ban::Entity),
    )
    .await?;
    legacy::ensure_temp_ban_cidr_column(db).await?;
    Ok(())
}

pub(super) async fn create_trusted_cidr_tables(
    db: &DatabaseConnection,
    schema: &Schema,
) -> Result<()> {
    create_table(
        db,
        schema.create_table_from_entity(entities::trusted_cidr::Entity),
    )
    .await?;
    Ok(())
}

pub(super) async fn create_node_tables(db: &DatabaseConnection, schema: &Schema) -> Result<()> {
    create_table(db, schema.create_table_from_entity(entities::node::Entity)).await?;
    legacy::ensure_node_interface_ips_column(db).await?;
    Ok(())
}

async fn create_table(
    db: &DatabaseConnection,
    mut stmt: sea_orm::sea_query::TableCreateStatement,
) -> Result<()> {
    stmt.if_not_exists();
    db.execute(&stmt).await?;
    Ok(())
}
