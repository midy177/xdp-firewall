pub mod entities;

use anyhow::{Context, Result, bail};
use sea_orm::sea_query::{Index, Value};
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
    ensure_firewall_rule_key_column(db).await?;
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
        schema.create_table_from_entity(entities::threat_source_state::Entity),
    )
    .await?;
    create_table(
        db,
        schema.create_table_from_entity(entities::threat_prefix::Entity),
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
    ensure_temp_ban_cidr_column(db).await?;
    ensure_firewall_rule_key_unique_index(db).await?;
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
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_threat_source_states_policy_name_source")
            .table(entities::threat_source_state::Entity.table_ref())
            .col(entities::threat_source_state::Column::PolicyName)
            .col(entities::threat_source_state::Column::SourceName)
            .unique()
            .to_owned(),
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_threat_prefixes_policy_name_source")
            .table(entities::threat_prefix::Entity.table_ref())
            .col(entities::threat_prefix::Column::PolicyName)
            .col(entities::threat_prefix::Column::SourceName)
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

async fn ensure_firewall_rule_key_unique_index(db: &DatabaseConnection) -> Result<()> {
    drop_index_if_exists(
        db,
        "idx_firewall_rules_policy_name_rule_key",
        "firewall_rules",
    )
    .await?;
    create_index(
        db,
        Index::create()
            .if_not_exists()
            .name("idx_firewall_rules_rule_key")
            .table(entities::firewall_rule::Entity.table_ref())
            .col(entities::firewall_rule::Column::RuleKey)
            .unique()
            .to_owned(),
    )
    .await?;
    Ok(())
}

async fn drop_index_if_exists(db: &DatabaseConnection, index: &str, table: &str) -> Result<()> {
    let backend = db.get_database_backend();
    if !index_exists(db, index, table).await? {
        return Ok(());
    }

    let sql = match backend {
        DbBackend::Postgres | DbBackend::Sqlite => format!("DROP INDEX {index}"),
        DbBackend::MySql => format!("DROP INDEX {index} ON {table}"),
        _ => bail!("unsupported database backend for index migration"),
    };
    db.execute_raw(raw_sql(backend, sql)).await?;
    Ok(())
}

async fn ensure_firewall_rule_key_column(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    if !column_exists(db, "firewall_rules", "rule_key").await? {
        let sql = match backend {
            DbBackend::Postgres => "ALTER TABLE firewall_rules ADD COLUMN rule_key VARCHAR(128)",
            DbBackend::MySql => "ALTER TABLE firewall_rules ADD COLUMN rule_key VARCHAR(128)",
            DbBackend::Sqlite => "ALTER TABLE firewall_rules ADD COLUMN rule_key TEXT",
            _ => bail!("unsupported database backend for firewall rule migration"),
        };
        db.execute_raw(raw_sql(backend, sql)).await?;
    }

    backfill_firewall_rule_keys(db).await?;
    ensure_firewall_rule_key_not_null(db).await?;
    Ok(())
}

async fn ensure_temp_ban_cidr_column(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();
    if !column_exists(db, "firewall_temp_bans", "cidr").await? {
        let sql = match backend {
            DbBackend::Postgres => "ALTER TABLE firewall_temp_bans ADD COLUMN cidr VARCHAR(128)",
            DbBackend::MySql => "ALTER TABLE firewall_temp_bans ADD COLUMN cidr VARCHAR(128)",
            DbBackend::Sqlite => "ALTER TABLE firewall_temp_bans ADD COLUMN cidr TEXT",
            _ => bail!("unsupported database backend for temporary ban migration"),
        };
        db.execute_raw(raw_sql(backend, sql)).await?;
    }

    backfill_temp_ban_cidrs(db).await?;
    drop_legacy_temp_ban_ip_column(db).await?;
    Ok(())
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
        let ip = row
            .try_get::<Option<String>>("", "ip")?
            .with_context(|| format!("temporary ban row {id} is missing legacy ip value"))?;
        let addr = ip
            .trim()
            .parse::<std::net::IpAddr>()
            .with_context(|| format!("invalid legacy temporary ban IP '{ip}'"))?;
        let cidr = match addr {
            std::net::IpAddr::V4(addr) => format!("{addr}/32"),
            std::net::IpAddr::V6(addr) => format!("{addr}/128"),
        };
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
    }

    Ok(())
}

async fn drop_legacy_temp_ban_ip_column(db: &DatabaseConnection) -> Result<()> {
    if !column_exists(db, "firewall_temp_bans", "ip").await? {
        return Ok(());
    }

    let backend = db.get_database_backend();
    match backend {
        DbBackend::Postgres => {
            db.execute_raw(raw_sql(
                backend,
                "ALTER TABLE firewall_temp_bans DROP COLUMN ip",
            ))
            .await?;
        }
        DbBackend::MySql => {
            db.execute_raw(raw_sql(
                backend,
                "ALTER TABLE firewall_temp_bans DROP COLUMN ip",
            ))
            .await?;
        }
        DbBackend::Sqlite => {
            rebuild_sqlite_temp_bans_without_legacy_ip(db).await?;
        }
        _ => bail!("unsupported database backend for temporary ban legacy IP migration"),
    }
    Ok(())
}

async fn rebuild_sqlite_temp_bans_without_legacy_ip(db: &DatabaseConnection) -> Result<()> {
    let backend = DbBackend::Sqlite;
    db.execute_raw(raw_sql(
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
    db.execute_raw(raw_sql(
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
    db.execute_raw(raw_sql(backend, "DROP TABLE firewall_temp_bans"))
        .await?;
    db.execute_raw(raw_sql(
        backend,
        "ALTER TABLE firewall_temp_bans_new RENAME TO firewall_temp_bans",
    ))
    .await?;
    Ok(())
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
        let priority = row.try_get::<i32>("", "priority")?;
        let action = row.try_get::<String>("", "action")?;
        let cidr = row.try_get::<String>("", "cidr")?;
        let protocol = row.try_get::<Option<String>>("", "protocol")?;
        let port = row.try_get::<Option<i32>>("", "port")?;
        let rule_key = entities::firewall_rule::generated_rule_key(
            priority,
            &action,
            &cidr,
            protocol.as_deref(),
            port,
        );
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
    }

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
            rebuild_sqlite_firewall_rules_with_required_rule_key(db).await?;
        }
        _ => bail!("unsupported database backend for firewall rule migration"),
    }
    Ok(())
}

async fn sqlite_column_is_not_null(
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

async fn rebuild_sqlite_firewall_rules_with_required_rule_key(
    db: &DatabaseConnection,
) -> Result<()> {
    let backend = DbBackend::Sqlite;
    db.execute_raw(raw_sql(
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
    db.execute_raw(raw_sql(
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
    db.execute_raw(raw_sql(backend, "DROP TABLE firewall_rules"))
        .await?;
    db.execute_raw(raw_sql(
        backend,
        "ALTER TABLE firewall_rules_new RENAME TO firewall_rules",
    ))
    .await?;
    Ok(())
}

async fn column_exists(db: &DatabaseConnection, table: &str, column: &str) -> Result<bool> {
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

async fn index_exists(db: &DatabaseConnection, index: &str, table: &str) -> Result<bool> {
    let backend = db.get_database_backend();
    let sql = match backend {
        DbBackend::Postgres => format!(
            "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND tablename = '{table}' AND indexname = '{index}'"
        ),
        DbBackend::MySql => format!(
            "SELECT 1 FROM information_schema.statistics WHERE table_schema = database() AND table_name = '{table}' AND index_name = '{index}'"
        ),
        DbBackend::Sqlite => format!("PRAGMA index_list('{table}')"),
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
        .any(|name| name == index))
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveModelTrait, Set};

    #[tokio::test]
    async fn migrate_backfills_and_requires_firewall_rule_key() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let db = Database::connect(options).await.unwrap();
        let backend = DbBackend::Sqlite;

        db.execute_raw(raw_sql(
            backend,
            "CREATE TABLE firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                policy_name TEXT NOT NULL,
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
        .await
        .unwrap();
        db.execute_raw(raw_sql(
            backend,
            "INSERT INTO firewall_rules (
                policy_name,
                enabled,
                priority,
                action,
                cidr,
                protocol,
                port,
                comment,
                updated_at
            ) VALUES (
                'default',
                TRUE,
                10,
                'deny',
                '203.0.113.0/24',
                'tcp',
                443,
                NULL,
                '2026-01-01 00:00:00'
            )",
        ))
        .await
        .unwrap();

        migrate(&db).await.unwrap();

        let row = db
            .query_one_raw(raw_sql(
                backend,
                "SELECT rule_key FROM firewall_rules WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap();
        let rule_key = row.try_get::<String>("", "rule_key").unwrap();
        assert_eq!(
            rule_key,
            entities::firewall_rule::generated_rule_key(
                10,
                "deny",
                "203.0.113.0/24",
                Some("tcp"),
                Some(443),
            )
        );
        assert!(
            sqlite_column_is_not_null(&db, "firewall_rules", "rule_key")
                .await
                .unwrap()
        );

        let insert_null = db
            .execute_raw(raw_sql(
                backend,
                "INSERT INTO firewall_rules (
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
                ) VALUES (
                    'default',
                    NULL,
                    TRUE,
                    20,
                    'allow',
                    '198.51.100.0/24',
                    'udp',
                    53,
                    NULL,
                    '2026-01-01 00:00:00'
                )",
            ))
            .await;
        assert!(insert_null.is_err());

        let insert_duplicate_rule_key = db
            .execute_raw(raw_sql(
                backend,
                format!(
                    "INSERT INTO firewall_rules (
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
                    ) VALUES (
                        'secondary',
                        '{}',
                        TRUE,
                        20,
                        'allow',
                        '198.51.100.0/24',
                        'udp',
                        53,
                        NULL,
                        '2026-01-01 00:00:00'
                    )",
                    rule_key
                ),
            ))
            .await;
        assert!(insert_duplicate_rule_key.is_err());
    }

    #[tokio::test]
    async fn migrate_backfills_temp_ban_cidr_and_drops_legacy_ip_column() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let db = Database::connect(options).await.unwrap();
        let backend = DbBackend::Sqlite;

        db.execute_raw(raw_sql(
            backend,
            "CREATE TABLE firewall_temp_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                policy_name TEXT NOT NULL,
                ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER,
                expires_at TIMESTAMP NOT NULL,
                comment TEXT,
                created_at TIMESTAMP NOT NULL
            )",
        ))
        .await
        .unwrap();
        db.execute_raw(raw_sql(
            backend,
            "INSERT INTO firewall_temp_bans (
                policy_name,
                ip,
                protocol,
                port,
                expires_at,
                comment,
                created_at
            ) VALUES (
                'edge',
                '203.0.113.10',
                'any',
                NULL,
                '2026-01-01 00:05:00',
                NULL,
                '2026-01-01 00:00:00'
            )",
        ))
        .await
        .unwrap();

        migrate(&db).await.unwrap();

        assert!(
            !column_exists(&db, "firewall_temp_bans", "ip")
                .await
                .unwrap()
        );
        let row = db
            .query_one_raw(raw_sql(
                backend,
                "SELECT cidr FROM firewall_temp_bans WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "cidr").unwrap(),
            "203.0.113.10/32"
        );

        entities::temp_ban::ActiveModel {
            policy_name: Set("edge".to_string()),
            cidr: Set("203.0.113.11/32".to_string()),
            protocol: Set("any".to_string()),
            port: Set(None),
            expires_at: Set(chrono::Utc::now().naive_utc()),
            comment: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
    }
}
