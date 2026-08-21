use anyhow::Result;
use sea_orm::{DatabaseConnection, Schema};

mod columns;
mod indexes;
mod legacy;
mod tables;
#[cfg(test)]
mod tests;

use columns::ensure_mysql_text_capacity;
use indexes::{
    create_dynamic_policy_indexes, create_geo_indexes, create_temp_ban_indexes,
    create_threat_indexes, create_trusted_cidr_indexes, ensure_firewall_rule_key_unique_index,
};
use tables::{
    create_dynamic_policy_tables, create_geo_tables, create_node_tables, create_policy_tables,
    create_temp_ban_tables, create_threat_tables, create_trusted_cidr_tables,
};

pub async fn migrate(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    create_policy_tables(db, &schema).await?;
    create_geo_tables(db, &schema).await?;
    create_threat_tables(db, &schema).await?;
    create_dynamic_policy_tables(db, &schema).await?;
    create_temp_ban_tables(db, &schema).await?;
    create_trusted_cidr_tables(db, &schema).await?;
    create_node_tables(db, &schema).await?;
    ensure_mysql_text_capacity(db).await?;
    create_geo_indexes(db).await?;
    create_dynamic_policy_indexes(db).await?;
    create_temp_ban_indexes(db).await?;
    create_trusted_cidr_indexes(db).await?;
    create_threat_indexes(db).await?;
    ensure_firewall_rule_key_unique_index(db).await?;
    Ok(())
}
