pub mod entities;

use anyhow::{Context, Result, bail};
use sea_orm::sea_query::Index;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, DbBackend,
    DbErr, EntityName, Schema, Statement,
};
use std::{env, time::Duration};

const DEFAULT_DB_MAX_CONNECTIONS: u32 = 16;
const DEFAULT_DB_MIN_CONNECTIONS: u32 = 1;
const DEFAULT_DB_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_DB_ACQUIRE_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_DB_IDLE_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_DB_MAX_LIFETIME_SECONDS: u64 = 1_800;

pub async fn connect(url: &str) -> Result<DatabaseConnection> {
    let mut options = ConnectOptions::new(url.to_string());
    let max_connections = env_u32(
        "XDP_FIREWALL_DB_MAX_CONNECTIONS",
        DEFAULT_DB_MAX_CONNECTIONS,
    )?;
    let min_connections = env_u32(
        "XDP_FIREWALL_DB_MIN_CONNECTIONS",
        DEFAULT_DB_MIN_CONNECTIONS,
    )?;
    if max_connections == 0 {
        bail!("XDP_FIREWALL_DB_MAX_CONNECTIONS must be greater than 0");
    }
    if min_connections > max_connections {
        bail!(
            "XDP_FIREWALL_DB_MIN_CONNECTIONS must be less than or equal to XDP_FIREWALL_DB_MAX_CONNECTIONS"
        );
    }

    options
        .max_connections(max_connections)
        .min_connections(min_connections)
        .connect_timeout(Duration::from_secs(env_u64(
            "XDP_FIREWALL_DB_CONNECT_TIMEOUT_SECONDS",
            DEFAULT_DB_CONNECT_TIMEOUT_SECONDS,
        )?))
        .acquire_timeout(Duration::from_secs(env_u64(
            "XDP_FIREWALL_DB_ACQUIRE_TIMEOUT_SECONDS",
            DEFAULT_DB_ACQUIRE_TIMEOUT_SECONDS,
        )?))
        .idle_timeout(Duration::from_secs(env_u64(
            "XDP_FIREWALL_DB_IDLE_TIMEOUT_SECONDS",
            DEFAULT_DB_IDLE_TIMEOUT_SECONDS,
        )?))
        .max_lifetime(Duration::from_secs(env_u64(
            "XDP_FIREWALL_DB_MAX_LIFETIME_SECONDS",
            DEFAULT_DB_MAX_LIFETIME_SECONDS,
        )?));

    Database::connect(options)
        .await
        .with_context(|| "failed to connect database")
}

fn env_u32(name: &str, default: u32) -> Result<u32> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .with_context(|| format!("{name} must be an unsigned integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("{name} must be an unsigned integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
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
    create_table(
        db,
        schema.create_table_from_entity(entities::threat_source::Entity),
    )
    .await?;
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
    create_table(
        db,
        schema.create_table_from_entity(entities::temp_ban::Entity),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_geo_country_catalog_code")
            .table(entities::geo_country_catalog::Entity.table_ref())
            .col(entities::geo_country_catalog::Column::Code)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_geo_ip_list_states_country")
            .table(entities::geo_ip_list_state::Entity.table_ref())
            .col(entities::geo_ip_list_state::Column::Country)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_geo_ip_prefixes_country")
            .table(entities::geo_ip_prefix::Entity.table_ref())
            .col(entities::geo_ip_prefix::Column::Country)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_dynamic_rate_limits_policy_name_priority")
            .table(entities::dynamic_rate_limit::Entity.table_ref())
            .col(entities::dynamic_rate_limit::Column::PolicyName)
            .col(entities::dynamic_rate_limit::Column::Priority)
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_temp_bans_policy_name_expires_at")
            .table(entities::temp_ban::Entity.table_ref())
            .col(entities::temp_ban::Column::PolicyName)
            .col(entities::temp_ban::Column::ExpiresAt)
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::trusted_cidr::Entity),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_trusted_cidrs_policy_name_cidr")
            .table(entities::trusted_cidr::Entity.table_ref())
            .col(entities::trusted_cidr::Column::PolicyName)
            .col(entities::trusted_cidr::Column::Cidr)
            .unique()
            .to_owned(),
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
    db.execute(&stmt).await?;
    Ok(())
}

async fn create_index(
    db: &DatabaseConnection,
    stmt: sea_orm::sea_query::IndexCreateStatement,
) -> Result<()> {
    db.execute(&stmt).await?;
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

pub async fn next_policy_version_in_transaction(
    txn: &DatabaseTransaction,
    policy_name: &str,
) -> std::result::Result<i64, DbErr> {
    use entities::policy_version::{ActiveModel, Entity};
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

    let current = Entity::find()
        .filter(entities::policy_version::Column::PolicyName.eq(policy_name))
        .one(txn)
        .await?;
    let next_version = current.as_ref().map_or(1, |row| row.version + 1);
    if let Some(row) = current {
        let mut active: ActiveModel = row.into();
        active.version = Set(next_version);
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        active.update(txn).await?;
    } else {
        ActiveModel {
            policy_name: Set(policy_name.to_string()),
            version: Set(next_version),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(txn)
        .await?;
    }
    Ok(next_version)
}

pub fn placeholder(backend: DbBackend, n: usize) -> String {
    match backend {
        DbBackend::Postgres => format!("${n}"),
        DbBackend::MySql | DbBackend::Sqlite => "?".to_string(),
        _ => "?".to_string(),
    }
}

pub fn raw_sql(backend: DbBackend, sql: impl Into<String>) -> Statement {
    Statement::from_string(backend, sql.into())
}
