use anyhow::{Context, Result, bail};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
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
