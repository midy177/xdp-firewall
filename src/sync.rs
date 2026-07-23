use crate::cli::{AgentArgs, SyncOnceArgs};
use crate::{firewall, xdp, xds};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::time::{Duration, interval};
use tracing::{error, info};

pub async fn sync_once(args: SyncOnceArgs) -> Result<()> {
    let node_id = resolve_node_id(args.node_id.as_deref())?;
    let policy = firewall::DEFAULT_POLICY_NAME;
    info!(
        node_id = %node_id,
        policy,
        control_url = %args.control_url,
        configured_interface = ?args.interface,
        xdp_mode = %args.xdp_mode.as_str(),
        xdp_object = %args.xdp_object,
        program = %args.program,
        "attaching XDP for sync-once"
    );
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp_object,
        &args.program,
        sync_once_map_sizes(&args),
        args.xdp_mode,
    )?;
    let interface = xdp.interface_name().to_string();
    let mut client = xds::XdsClient::connect(xds::XdsClientConfig {
        control_url: args.control_url.clone(),
        agent_token: args.agent_token.clone(),
    })
    .await?;
    let Some((version, snapshot)) = client.fetch_policy(&node_id, &interface, -1).await? else {
        bail!("xDS control plane returned unchanged policy for initial sync");
    };
    let applied = apply_latest(&mut xdp, snapshot, &args.control_url, version).await?;
    let (status, error) = sync_once_status();
    client
        .report_heartbeat(&node_id, &interface, applied, status, error.as_deref())
        .await?;
    info!(
        node_id = %node_id,
        policy,
        interface = %interface,
        xds_version = version,
        version = applied,
        "policy synced once"
    );
    Ok(())
}

pub async fn run_agent(args: AgentArgs) -> Result<()> {
    validate_positive_interval("heartbeat-seconds", args.heartbeat_seconds)?;
    let node_id = resolve_node_id(args.node_id.as_deref())?;
    let policy = firewall::DEFAULT_POLICY_NAME;
    info!(
        node_id = %node_id,
        policy,
        control_url = %args.control_url,
        configured_interface = ?args.interface,
        xdp_mode = %args.xdp_mode.as_str(),
        xdp_object = %args.xdp_object,
        program = %args.program,
        heartbeat_seconds = args.heartbeat_seconds,
        rule_map_entries = args.rule_map_entries,
        geo_map_entries = args.geo_map_entries,
        trusted_map_entries = args.trusted_map_entries,
        country_map_entries = args.country_map_entries,
        rate_map_entries = args.rate_map_entries,
        "attaching XDP for agent"
    );
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp_object,
        &args.program,
        agent_map_sizes(&args),
        args.xdp_mode,
    )?;
    let interface = xdp.interface_name().to_string();
    info!(
        node_id = %node_id,
        policy,
        interface = %interface,
        "agent attached XDP"
    );
    let mut applied_version = -1_i64;
    let heartbeat_interval = Duration::from_secs(args.heartbeat_seconds);
    let reconnect_delay = heartbeat_interval.min(Duration::from_secs(10));
    let mut client = xds::XdsClient::connect(xds::XdsClientConfig {
        control_url: args.control_url.clone(),
        agent_token: args.agent_token.clone(),
    })
    .await?;
    client
        .report_heartbeat(&node_id, &interface, 0, "starting", None)
        .await?;

    loop {
        let mut stream = match client
            .stream_policy(&node_id, &interface, applied_version)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                let details = format!("{err:#}");
                error!(error = %details, "failed to subscribe to xDS policy stream");
                let _ = client
                    .report_heartbeat(
                        &node_id,
                        &interface,
                        applied_version.max(0),
                        "error",
                        Some(&details),
                    )
                    .await;
                tokio::time::sleep(reconnect_delay).await;
                client = xds::XdsClient::connect(xds::XdsClientConfig {
                    control_url: args.control_url.clone(),
                    agent_token: args.agent_token.clone(),
                })
                .await?;
                continue;
            }
        };
        let mut heartbeat_tick = interval(heartbeat_interval);
        loop {
            tokio::select! {
                update = stream.message() => {
                    match update {
                        Ok(Some(update)) => {
                            let (version, snapshot) = xds::XdsClient::policy_from_update(update)?;
                            match apply_latest(&mut xdp, snapshot, &args.control_url, version).await {
                                Ok(applied) => {
                                    applied_version = applied;
                                    client.report_heartbeat(&node_id, &interface, applied_version, "ok", None).await?;
                                }
                                Err(err) => {
                                    let details = format!("{err:#}");
                                    error!(error = %details, "failed to apply firewall policy");
                                    client.report_heartbeat(&node_id, &interface, applied_version.max(0), "error", Some(&details)).await?;
                                }
                            }
                        }
                        Ok(None) => {
                            info!("xDS policy stream closed; reconnecting");
                            tokio::time::sleep(reconnect_delay).await;
                            break;
                        }
                        Err(err) => {
                            let details = format!("{err:#}");
                            error!(error = %details, "xDS policy stream failed; reconnecting");
                            let _ = client.report_heartbeat(&node_id, &interface, applied_version.max(0), "error", Some(&details)).await;
                            tokio::time::sleep(reconnect_delay).await;
                            break;
                        }
                    }
                }
                _ = heartbeat_tick.tick() => {
                    client.report_heartbeat(&node_id, &interface, applied_version.max(0), "ok", None).await?;
                }
                result = tokio::signal::ctrl_c() => {
                    result?;
                    client.report_heartbeat(&node_id, &interface, applied_version.max(0), "stopped", None).await?;
                    return Ok(());
                }
            }
        }
    }
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
    xdp: &mut xdp::XdpManager,
    mut snapshot: firewall::PolicySnapshot,
    control_url: &str,
    expected_version: i64,
) -> Result<i64> {
    let policy = firewall::DEFAULT_POLICY_NAME;
    add_control_plane_allow_rules(&mut snapshot, control_url).await?;
    let compiled = firewall::compile_policy(&snapshot).await?;
    xdp.apply(&compiled)?;
    info!(
        policy,
        expected_version,
        applied_version = compiled.version,
        "applied firewall policy"
    );
    Ok(compiled.version)
}

async fn add_control_plane_allow_rules(
    snapshot: &mut firewall::PolicySnapshot,
    control_url: &str,
) -> Result<()> {
    let prefixes = resolve_control_plane_prefixes(control_url).await?;
    for cidr in prefixes {
        snapshot.rules.push(firewall::FirewallRule {
            priority: i32::MIN,
            action: firewall::RuleAction::Allow,
            cidr,
            protocol: firewall::L4Protocol::Any,
            port: None,
            comment: Some("local xDS control-plane allow".to_string()),
        });
    }
    Ok(())
}

async fn resolve_control_plane_prefixes(control_url: &str) -> Result<Vec<IpNet>> {
    let (host, port) = control_plane_host_port(control_url)?;
    let addresses = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("failed to resolve xDS control plane host '{host}'"))?;
    let mut prefixes = Vec::new();
    for address in addresses {
        let ip = address.ip();
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let cidr = IpNet::new(ip, prefix)
            .with_context(|| format!("failed to build xDS control-plane CIDR for {ip}"))?;
        if !prefixes.contains(&cidr) {
            prefixes.push(cidr);
        }
    }
    Ok(prefixes)
}

fn control_plane_host_port(control_url: &str) -> Result<(String, u16)> {
    let without_scheme = control_url
        .strip_prefix("http://")
        .or_else(|| control_url.strip_prefix("https://"))
        .unwrap_or(control_url);
    let authority = without_scheme
        .split('/')
        .next()
        .filter(|value| !value.is_empty())
        .context("xDS control URL is missing a host")?;
    if let Some(host) = authority.strip_prefix('[') {
        let (host, rest) = host
            .split_once(']')
            .context("invalid bracketed IPv6 xDS control URL host")?;
        let port = rest
            .strip_prefix(':')
            .map(str::parse)
            .transpose()?
            .unwrap_or(50051);
        return Ok((host.to_string(), port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(host, port)| {
            let port = port
                .parse::<u16>()
                .context("invalid xDS control URL port")?;
            Ok::<_, anyhow::Error>((host.to_string(), port))
        })
        .transpose()?
        .unwrap_or_else(|| (authority.to_string(), 50051));
    Ok((host, port))
}
