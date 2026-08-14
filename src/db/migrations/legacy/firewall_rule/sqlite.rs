use crate::db::sql::raw_sql;
use anyhow::Result;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, TransactionTrait};

pub(super) async fn rebuild_firewall_rules_with_required_rule_key(
    db: &DatabaseConnection,
) -> Result<()> {
    let backend = DbBackend::Sqlite;
    let txn = db.begin().await?;
    txn.execute_raw(raw_sql(
        backend,
        "CREATE TABLE firewall_rules_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            policy_name TEXT NOT NULL,
            rule_key TEXT NOT NULL,
            enabled BOOLEAN NOT NULL,
            priority INTEGER NOT NULL,
            action TEXT NOT NULL,
            cidr TEXT NOT NULL,
            protocol TEXT,
            port INTEGER,
            comment TEXT,
            updated_at TIMESTAMP NOT NULL
        )",
    ))
    .await?;
    txn.execute_raw(raw_sql(
        backend,
        "INSERT INTO firewall_rules_new (
            id,
            policy_name,
            rule_key,
            enabled,
            priority,
            action,
            cidr,
            protocol,
            port,
            comment,
            updated_at
        )
        SELECT
            id,
            policy_name,
            rule_key,
            enabled,
            priority,
            action,
            cidr,
            protocol,
            port,
            comment,
            updated_at
        FROM firewall_rules",
    ))
    .await?;
    txn.execute_raw(raw_sql(backend, "DROP TABLE firewall_rules"))
        .await?;
    txn.execute_raw(raw_sql(
        backend,
        "ALTER TABLE firewall_rules_new RENAME TO firewall_rules",
    ))
    .await?;
    txn.commit().await?;
    Ok(())
}
