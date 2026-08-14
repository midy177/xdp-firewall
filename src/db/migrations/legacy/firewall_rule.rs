use super::schema::{column_exists, sqlite_column_is_not_null};
use crate::db::{
    entities,
    sql::{placeholder, raw_sql},
};
use anyhow::{Result, bail};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, sea_query::Value};

mod sqlite;

pub(in crate::db::migrations) async fn ensure_firewall_rule_key_column(
    db: &DatabaseConnection,
) -> Result<()> {
    let backend = db.get_database_backend();
    if !column_exists(db, "firewall_rules", "rule_key").await? {
        db.execute_raw(raw_sql(backend, add_rule_key_column_sql(backend)?))
            .await?;
    }

    backfill_firewall_rule_keys(db).await?;
    ensure_firewall_rule_key_not_null(db).await?;
    Ok(())
}

fn add_rule_key_column_sql(backend: DbBackend) -> Result<&'static str> {
    match backend {
        DbBackend::Postgres | DbBackend::MySql => {
            Ok("ALTER TABLE firewall_rules ADD COLUMN rule_key VARCHAR(128)")
        }
        DbBackend::Sqlite => Ok("ALTER TABLE firewall_rules ADD COLUMN rule_key TEXT"),
        _ => bail!("unsupported database backend for firewall rule migration"),
    }
}

async fn backfill_firewall_rule_keys(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    let rows = db
        .query_all_raw(raw_sql(
            backend,
            "SELECT id, priority, action, cidr, protocol, port FROM firewall_rules WHERE rule_key IS NULL OR TRIM(rule_key) = ''",
        ))
        .await?;

    for row in rows {
        let id = row.try_get::<i32>("", "id")?;
        let rule_key = entities::firewall_rule::generated_rule_key(
            row.try_get::<i32>("", "priority")?,
            &row.try_get::<String>("", "action")?,
            &row.try_get::<String>("", "cidr")?,
            row.try_get::<Option<String>>("", "protocol")?.as_deref(),
            row.try_get::<Option<i32>>("", "port")?,
        );
        update_firewall_rule_key(db, backend, id, rule_key).await?;
    }

    Ok(())
}

async fn update_firewall_rule_key(
    db: &DatabaseConnection,
    backend: DbBackend,
    id: i32,
    rule_key: String,
) -> Result<()> {
    db.execute_raw(Statement::from_sql_and_values(
        backend,
        format!(
            "UPDATE firewall_rules SET rule_key = {} WHERE id = {}",
            placeholder(backend, 1),
            placeholder(backend, 2)
        ),
        vec![Value::String(Some(rule_key)), Value::Int(Some(id))],
    ))
    .await?;
    Ok(())
}

async fn ensure_firewall_rule_key_not_null(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    match backend {
        DbBackend::Postgres => {
            db.execute_raw(raw_sql(
                backend,
                "ALTER TABLE firewall_rules ALTER COLUMN rule_key SET NOT NULL",
            ))
            .await?;
        }
        DbBackend::MySql => {
            db.execute_raw(raw_sql(
                backend,
                "ALTER TABLE firewall_rules MODIFY rule_key VARCHAR(128) NOT NULL",
            ))
            .await?;
        }
        DbBackend::Sqlite => {
            if sqlite_column_is_not_null(db, "firewall_rules", "rule_key").await? {
                return Ok(());
            }
            sqlite::rebuild_firewall_rules_with_required_rule_key(db).await?;
        }
        _ => bail!("unsupported database backend for firewall rule migration"),
    }
    Ok(())
}
