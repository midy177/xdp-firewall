use crate::db::sql::raw_sql;
use anyhow::{Result, bail};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend};

pub(in crate::db::migrations) async fn column_exists(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> Result<bool> {
    let backend = db.get_database_backend();
    let sql = match backend {
        DbBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '{table}' AND column_name = '{column}'"
        ),
        DbBackend::MySql => format!(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = database() AND table_name = '{table}' AND column_name = '{column}'"
        ),
        DbBackend::Sqlite => format!("PRAGMA table_info('{table}')"),
        _ => bail!("unsupported database backend for schema inspection"),
    };

    if backend != DbBackend::Sqlite {
        return Ok(db.query_one_raw(raw_sql(backend, sql)).await?.is_some());
    }

    Ok(db
        .query_all_raw(raw_sql(backend, sql))
        .await?
        .into_iter()
        .map(|row| row.try_get::<String>("", "name"))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .any(|name| name == column))
}

pub(in crate::db::migrations) async fn sqlite_column_is_not_null(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> Result<bool> {
    let rows = db
        .query_all_raw(raw_sql(
            DbBackend::Sqlite,
            format!("PRAGMA table_info('{table}')"),
        ))
        .await?;
    for row in rows {
        let name = row.try_get::<String>("", "name")?;
        if name == column {
            let not_null = row.try_get::<i32>("", "notnull")?;
            return Ok(not_null != 0);
        }
    }
    Ok(false)
}
