use crate::db::sql::raw_sql;
use anyhow::Result;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, TransactionTrait};

pub(super) async fn rebuild_temp_bans_without_legacy_ip(db: &DatabaseConnection) -> Result<()> {
    let backend = DbBackend::Sqlite;
    let txn = db.begin().await?;
    txn.execute_raw(raw_sql(
        backend,
        "CREATE TABLE firewall_temp_bans_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            policy_name TEXT NOT NULL,
            cidr TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER,
            expires_at TIMESTAMP NOT NULL,
            comment TEXT,
            created_at TIMESTAMP NOT NULL
        )",
    ))
    .await?;
    txn.execute_raw(raw_sql(
        backend,
        "INSERT INTO firewall_temp_bans_new (
            id,
            policy_name,
            cidr,
            protocol,
            port,
            expires_at,
            comment,
            created_at
        )
        SELECT
            id,
            policy_name,
            cidr,
            protocol,
            port,
            expires_at,
            comment,
            created_at
        FROM firewall_temp_bans",
    ))
    .await?;
    txn.execute_raw(raw_sql(backend, "DROP TABLE firewall_temp_bans"))
        .await?;
    txn.execute_raw(raw_sql(
        backend,
        "ALTER TABLE firewall_temp_bans_new RENAME TO firewall_temp_bans",
    ))
    .await?;
    txn.commit().await?;
    Ok(())
}
