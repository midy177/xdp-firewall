use crate::cli::{AgentArgs, SyncOnceArgs};
use crate::db::entities::{node, policy_version};
use crate::{firewall, security, xdp};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::collections::HashSet;
use tokio::time::{Duration, interval};
use tracing::{error, info};

pub async fn sync_once(db: DatabaseConnection, args: SyncOnceArgs) -> Result<()> {
    let node_id = resolve_node_id(args.node_id.as_deref())?;
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp_object,
        &args.program,
        sync_once_map_sizes(&args),
    )?;
    let interface = xdp.interface_name().to_string();
    let snapshot = firewall::load_policy(&db, &args.policy).await?;
    let mut compiled = firewall::compile_policy(&snapshot).await?;
    compiled.trusted_prefixes = trusted_prefixes(&args.trusted_cidrs)?;
    xdp.apply(&compiled)?;
    let (status, error) = sync_once_status();
    heartbeat(
        &db,
        &node_id,
        &args.policy,
        &interface,
        compiled.version,
        status,
        error,
    )
    .await?;
    info!(
        node_id = %node_id,
        policy = %args.policy,
        interface = %interface,
        version = compiled.version,
        "policy synced once"
    );
    Ok(())
}

pub async fn run_agent(db: DatabaseConnection, args: AgentArgs) -> Result<()> {
    validate_positive_interval("poll-seconds", args.poll_seconds)?;
    validate_positive_interval("heartbeat-seconds", args.heartbeat_seconds)?;
    let node_id = resolve_node_id(args.node_id.as_deref())?;
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp_object,
        &args.program,
        agent_map_sizes(&args),
    )?;
    let interface = xdp.interface_name().to_string();
    let mut poll = interval(Duration::from_secs(args.poll_seconds));
    let mut heartbeat_tick = interval(Duration::from_secs(args.heartbeat_seconds));
    let mut applied_version = -1_i64;

    heartbeat(&db, &node_id, &args.policy, &interface, 0, "starting", None).await?;

    loop {
        tokio::select! {
            _ = poll.tick() => {
                match latest_version(&db, &args.policy).await {
                    Ok(version) if version != applied_version => {
                        match apply_latest(&db, &mut xdp, &args, version).await {
                            Ok(applied) => {
                                applied_version = applied;
                                heartbeat(&db, &node_id, &args.policy, &interface, applied_version, "ok", None).await?;
                            }
                            Err(err) => {
                                let details = format!("{err:#}");
                                let message = security::public_error_message(&details);
                                error!(error = %details, "failed to apply firewall policy");
                                heartbeat(&db, &node_id, &args.policy, &interface, applied_version.max(0), "error", Some(message)).await?;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let details = format!("{err:#}");
                        let message = security::public_error_message(&details);
                        error!(error = %details, "failed to read firewall policy version");
                        heartbeat(&db, &node_id, &args.policy, &interface, applied_version.max(0), "error", Some(message)).await?;
                    }
                }
            }
            _ = heartbeat_tick.tick() => {
                heartbeat(&db, &node_id, &args.policy, &interface, applied_version.max(0), "ok", None).await?;
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                heartbeat(&db, &node_id, &args.policy, &interface, applied_version.max(0), "stopped", None).await?;
                break;
            }
        }
    }
    Ok(())
}

fn validate_positive_interval(name: &str, seconds: u64) -> Result<()> {
    if seconds == 0 {
        bail!("{name} must be greater than 0");
    }
    Ok(())
}

fn sync_once_status() -> (&'static str, Option<String>) {
    #[cfg(target_os = "linux")]
    {
        (
            "sync-once-completed",
            Some(
                "sync-once exits after applying maps; use agent for persistent XDP enforcement"
                    .to_string(),
            ),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        ("ok", None)
    }
}

fn agent_map_sizes(args: &AgentArgs) -> xdp::XdpMapSizes {
    xdp::XdpMapSizes {
        rule_entries: args.rule_map_entries,
        geo_entries: args.geo_map_entries,
        trusted_entries: args.trusted_map_entries,
        country_entries: args.country_map_entries,
        rate_entries: args.rate_map_entries,
    }
}

fn sync_once_map_sizes(args: &SyncOnceArgs) -> xdp::XdpMapSizes {
    xdp::XdpMapSizes {
        rule_entries: args.rule_map_entries,
        geo_entries: args.geo_map_entries,
        trusted_entries: args.trusted_map_entries,
        country_entries: args.country_map_entries,
        rate_entries: args.rate_map_entries,
    }
}

fn resolve_node_id(configured: Option<&str>) -> Result<String> {
    if let Some(value) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(value.to_string());
    }
    for key in ["XDP_FIREWALL_NODE_ID", "NODE_ID", "HOSTNAME"] {
        if let Some(value) = std::env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return Ok(value);
        }
    }
    let hostname = std::fs::read_to_string("/etc/hostname")
        .context("node id was not configured and /etc/hostname could not be read")?;
    hostname
        .lines()
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .context("node id was not configured and /etc/hostname is empty")
}

async fn apply_latest(
    db: &DatabaseConnection,
    xdp: &mut xdp::XdpManager,
    args: &AgentArgs,
    expected_version: i64,
) -> Result<i64> {
    let snapshot = firewall::load_policy(db, &args.policy).await?;
    let mut compiled = firewall::compile_policy(&snapshot).await?;
    compiled.trusted_prefixes = trusted_prefixes(&args.trusted_cidrs)?;
    xdp.apply(&compiled)?;
    info!(
        policy = %args.policy,
        expected_version,
        applied_version = compiled.version,
        "applied firewall policy"
    );
    Ok(compiled.version)
}

fn trusted_prefixes(values: &[String]) -> Result<Vec<firewall::XdpTrustedPrefix>> {
    let mut unique = HashSet::new();
    let mut prefixes = Vec::new();
    for value in values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let net = value
            .parse::<IpNet>()
            .with_context(|| format!("invalid trusted CIDR '{value}'"))?;
        let prefix = match net {
            IpNet::V4(net) => firewall::XdpTrustedPrefix {
                addr: net.network().into(),
                prefix: net.prefix_len(),
            },
            IpNet::V6(net) => firewall::XdpTrustedPrefix {
                addr: net.network().into(),
                prefix: net.prefix_len(),
            },
        };
        if unique.insert((prefix.addr, prefix.prefix)) {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

async fn latest_version(db: &DatabaseConnection, policy_name: &str) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(policy_name))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

async fn heartbeat(
    db: &DatabaseConnection,
    node_id: &str,
    policy_name: &str,
    interface_name: &str,
    last_applied_version: i64,
    status: &str,
    error: Option<String>,
) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let public_error = error.as_deref().map(security::public_error_message);
    if let Some(row) = node::Entity::find_by_id(node_id.to_string())
        .one(db)
        .await?
    {
        let mut active: node::ActiveModel = row.into();
        active.policy_name = Set(policy_name.to_string());
        active.interface_name = Set(interface_name.to_string());
        active.last_seen_at = Set(now);
        active.last_applied_version = Set(last_applied_version);
        active.status = Set(status.to_string());
        active.error = Set(public_error);
        active.update(db).await?;
    } else {
        node::ActiveModel {
            node_id: Set(node_id.to_string()),
            policy_name: Set(policy_name.to_string()),
            interface_name: Set(interface_name.to_string()),
            last_seen_at: Set(now),
            last_applied_version: Set(last_applied_version),
            status: Set(status.to_string()),
            error: Set(public_error),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parses_trusted_prefixes_from_repeated_and_comma_values() {
        let prefixes = trusted_prefixes(&[
            "10.1.2.3/8".to_string(),
            "192.168.0.0/16,10.0.0.0/8".to_string(),
        ])
        .unwrap();

        assert_eq!(prefixes.len(), 2);
        assert!(prefixes.contains(&firewall::XdpTrustedPrefix {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        }));
        assert!(prefixes.contains(&firewall::XdpTrustedPrefix {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix: 16,
        }));
    }
}
