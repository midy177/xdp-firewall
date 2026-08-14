use super::schema::column_exists;
use crate::db::sql::{placeholder, raw_sql};
use anyhow::{Context, Result, bail};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, sea_query::Value};

mod sqlite;

pub(in crate::db::migrations) async fn ensure_temp_ban_cidr_column(
    db: &DatabaseConnection,
) -> Result<()> {
    let backend = db.get_database_backend();
    if !column_exists(db, "firewall_temp_bans", "cidr").await? {
        db.execute_raw(raw_sql(backend, add_temp_ban_cidr_column_sql(backend)?))
            .await?;
    }

    backfill_temp_ban_cidrs(db).await?;
    drop_legacy_temp_ban_ip_column(db).await?;
    Ok(())
}

fn add_temp_ban_cidr_column_sql(backend: DbBackend) -> Result<&'static str> {
    match backend {
        DbBackend::Postgres | DbBackend::MySql => {
            Ok("ALTER TABLE firewall_temp_bans ADD COLUMN cidr VARCHAR(128)")
        }
        DbBackend::Sqlite => Ok("ALTER TABLE firewall_temp_bans ADD COLUMN cidr TEXT"),
        _ => bail!("unsupported database backend for temporary ban migration"),
    }
}

async fn backfill_temp_ban_cidrs(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    if !column_exists(db, "firewall_temp_bans", "ip").await? {
        return Ok(());
    }

    let rows = db
        .query_all_raw(raw_sql(
            backend,
            "SELECT id, cidr, ip FROM firewall_temp_bans WHERE cidr IS NULL OR TRIM(cidr) = ''",
        ))
        .await?;

    for row in rows {
        let id = row.try_get::<i32>("", "id")?;
        let cidr = legacy_ip_to_cidr(
            row.try_get::<Option<String>>("", "ip")?
                .with_context(|| format!("temporary ban row {id} is missing legacy ip value"))?,
        )?;
        update_temp_ban_cidr(db, backend, id, cidr).await?;
    }

    Ok(())
}

fn legacy_ip_to_cidr(ip: String) -> Result<String> {
    let addr = ip
        .trim()
        .parse::<std::net::IpAddr>()
        .with_context(|| format!("invalid legacy temporary ban IP '{ip}'"))?;
    Ok(match addr {
        std::net::IpAddr::V4(addr) => format!("{addr}/32"),
        std::net::IpAddr::V6(addr) => format!("{addr}/128"),
    })
}

async fn update_temp_ban_cidr(
    db: &DatabaseConnection,
    backend: DbBackend,
    id: i32,
    cidr: String,
) -> Result<()> {
    db.execute_raw(Statement::from_sql_and_values(
        backend,
        format!(
            "UPDATE firewall_temp_bans SET cidr = {} WHERE id = {}",
            placeholder(backend, 1),
            placeholder(backend, 2)
        ),
        vec![Value::String(Some(cidr)), Value::Int(Some(id))],
    ))
    .await?;
    Ok(())
}

async fn drop_legacy_temp_ban_ip_column(db: &DatabaseConnection) -> Result<()> {
    if !column_exists(db, "firewall_temp_bans", "ip").await? {
        return Ok(());
    }

    let backend = db.get_database_backend();
    match backend {
        DbBackend::Postgres | DbBackend::MySql => {
            db.execute_raw(raw_sql(
                backend,
                "ALTER TABLE firewall_temp_bans DROP COLUMN ip",
            ))
            .await?;
        }
        DbBackend::Sqlite => {
            sqlite::rebuild_temp_bans_without_legacy_ip(db).await?;
        }
        _ => bail!("unsupported database backend for temporary ban legacy IP migration"),
    }
    Ok(())
}
