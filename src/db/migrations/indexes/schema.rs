use crate::db::sql::raw_sql;
use anyhow::{Result, bail};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend};

pub(super) async fn create_index(
    db: &DatabaseConnection,
    stmt: sea_orm::sea_query::IndexCreateStatement,
) -> Result<()> {
    db.execute(&stmt).await?;
    Ok(())
}

pub(super) async fn drop_index_if_exists(
    db: &DatabaseConnection,
    index: &str,
    table: &str,
) -> Result<()> {
    let backend = db.get_database_backend();
    if !index_exists(db, index, table).await? {
        return Ok(());
    }

    db.execute_raw(raw_sql(backend, drop_index_sql(backend, index, table)?))
        .await?;
    Ok(())
}

fn drop_index_sql(backend: DbBackend, index: &str, table: &str) -> Result<String> {
    match backend {
        DbBackend::Postgres | DbBackend::Sqlite => Ok(format!("DROP INDEX {index}")),
        DbBackend::MySql => Ok(format!("DROP INDEX {index} ON {table}")),
        _ => bail!("unsupported database backend for index migration"),
    }
}

async fn index_exists(db: &DatabaseConnection, index: &str, table: &str) -> Result<bool> {
    let backend = db.get_database_backend();
    let sql = index_exists_sql(backend, index, table)?;

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
        .any(|name| name == index))
}

fn index_exists_sql(backend: DbBackend, index: &str, table: &str) -> Result<String> {
    match backend {
        DbBackend::Postgres => Ok(format!(
            "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND tablename = '{table}' AND indexname = '{index}'"
        )),
        DbBackend::MySql => Ok(format!(
            "SELECT 1 FROM information_schema.statistics WHERE table_schema = database() AND table_name = '{table}' AND index_name = '{index}'"
        )),
        DbBackend::Sqlite => Ok(format!("PRAGMA index_list('{table}')")),
        _ => bail!("unsupported database backend for schema inspection"),
    }
}
