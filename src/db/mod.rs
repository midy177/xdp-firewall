pub mod entities;

use anyhow::{Context, Result};
use sea_orm::sea_query::Index;
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityName, Schema, Statement,
};

pub async fn connect(url: &str) -> Result<DatabaseConnection> {
    Database::connect(url)
        .await
        .with_context(|| "failed to connect database")
}

pub async fn migrate(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
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
    create_table(
        db,
        schema.create_table_from_entity(entities::geo_country_policy::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::threat_source::Entity),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_threat_sources_policy_name_name")
            .table(entities::threat_source::Entity.table_ref())
            .col(entities::threat_source::Column::PolicyName)
            .col(entities::threat_source::Column::Name)
            .unique()
            .to_owned(),
    )
    .await?;
    create_table(db, schema.create_table_from_entity(entities::node::Entity)).await?;
    Ok(())
}

async fn create_table(
    db: &DatabaseConnection,
    mut stmt: sea_orm::sea_query::TableCreateStatement,
) -> Result<()> {
    stmt.if_not_exists();
    let sql = db.get_database_backend().build(&stmt);
    db.execute(sql).await?;
    Ok(())
}

async fn create_index(
    db: &DatabaseConnection,
    stmt: sea_orm::sea_query::IndexCreateStatement,
) -> Result<()> {
    let sql = db.get_database_backend().build(&stmt);
    db.execute(sql).await?;
    Ok(())
}

pub async fn next_policy_version(db: &DatabaseConnection, policy_name: &str) -> Result<i64> {
    use entities::policy_version::{ActiveModel, Entity};
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

    let current = Entity::find()
        .filter(entities::policy_version::Column::PolicyName.eq(policy_name))
        .one(db)
        .await?;
    let next_version = current.as_ref().map_or(1, |row| row.version + 1);
    if let Some(row) = current {
        let mut active: ActiveModel = row.into();
        active.version = Set(next_version);
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        active.update(db).await?;
    } else {
        ActiveModel {
            policy_name: Set(policy_name.to_string()),
            version: Set(next_version),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(db)
        .await?;
    }
    Ok(next_version)
}

pub fn placeholder(backend: DbBackend, n: usize) -> String {
    match backend {
        DbBackend::Postgres => format!("${n}"),
        DbBackend::MySql | DbBackend::Sqlite => "?".to_string(),
    }
}

pub fn raw_sql(backend: DbBackend, sql: impl Into<String>) -> Statement {
    Statement::from_string(backend, sql.into())
}
