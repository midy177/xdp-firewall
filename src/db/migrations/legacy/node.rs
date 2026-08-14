use super::schema::column_exists;
use crate::db::sql::raw_sql;
use anyhow::{Result, bail};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend};

pub(in crate::db::migrations) async fn ensure_node_interface_ips_column(
    db: &DatabaseConnection,
) -> Result<()> {
    let backend = db.get_database_backend();
    if column_exists(db, "firewall_nodes", "interface_ips").await? {
        return Ok(());
    }
    db.execute_raw(raw_sql(
        backend,
        add_node_interface_ips_column_sql(backend)?,
    ))
    .await?;
    Ok(())
}

fn add_node_interface_ips_column_sql(backend: DbBackend) -> Result<&'static str> {
    match backend {
        DbBackend::Postgres | DbBackend::MySql => Ok(
            "ALTER TABLE firewall_nodes ADD COLUMN interface_ips VARCHAR(1024) NOT NULL DEFAULT ''",
        ),
        DbBackend::Sqlite => {
            Ok("ALTER TABLE firewall_nodes ADD COLUMN interface_ips TEXT NOT NULL DEFAULT ''")
        }
        _ => bail!("unsupported database backend for node migration"),
    }
}
