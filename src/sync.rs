use crate::cli::{AgentArgs, SyncOnceArgs};
use crate::{firewall, monitor, xdp, xds};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

pub async fn sync_once(args: SyncOnceArgs) -> Result<()> {
    let node_id = resolve_node_id(args.node_id.as_deref())?;
    let policy = firewall::DEFAULT_POLICY_NAME;
    info!(
        node_id = %node_id,
        policy,
        control_url = %args.control_url,
        configured_interface = ?args.interface,
        xdp_mode = %args.xdp_mode.as_str(),
        xdp_attach_strategy = %args.xdp_attach_strategy.as_str(),
        xdp_allow_replace = args.xdp_allow_replace,
        xdp_run_priority = args.xdp_run_priority,
        xdp_object = %args.xdp_object,
        program = %args.program,
        "attaching XDP for sync-once"
    );
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp_object,
        &args.program,
        sync_once_map_sizes(&args),
        xdp_attach_options_for_sync_once(&args),
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
        xdp_attach_strategy = %args.xdp_attach_strategy.as_str(),
        xdp_allow_replace = args.xdp_allow_replace,
        xdp_run_priority = args.xdp_run_priority,
        xdp_object = %args.xdp_object,
        program = %args.program,
        heartbeat_seconds = args.heartbeat_seconds,
        rule_map_entries = args.rule_map_entries,
        geo_map_entries = args.geo_map_entries,
        trusted_map_entries = args.trusted_map_entries,
        country_map_entries = args.country_map_entries,
        rate_map_entries = args.rate_map_entries,
        custom_rate_limit_map_entries = args.custom_rate_limit_map_entries,
        temp_ban_map_entries = args.temp_ban_map_entries,
        "attaching XDP for agent"
    );
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp_object,
        &args.program,
        agent_map_sizes(&args),
        xdp_attach_options_for_agent(&args),
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
    let mut drop_monitor: Option<tokio::task::JoinHandle<()>> = None;

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
                            let (version, snapshot, drop_monitor_enabled) =
                                match client.policy_from_update(update).await {
                                    Ok(update) => update,
                                    Err(err) => {
                                        let details = format!("{err:#}");
                                        error!(error = %details, "failed to decode xDS policy update");
                                        client.report_heartbeat(
                                            &node_id,
                                            &interface,
                                            applied_version.max(0),
                                            "error",
                                            Some(&details),
                                        ).await?;
                                        tokio::time::sleep(reconnect_delay).await;
                                        break;
                                    }
                                };
                            reconcile_drop_monitor(
                                &mut xdp,
                                &mut drop_monitor,
                                drop_monitor_enabled,
                                &args,
                                &node_id,
                                &interface,
                            )?;
                            if let Some(snapshot) = snapshot {
                                match apply_latest(&mut xdp, snapshot, &args.control_url, version).await {
                                    Ok(applied) => {
                                        applied_version = applied;
                                        log_xdp_stats(&xdp);
                                        client.report_heartbeat(&node_id, &interface, applied_version, "ok", None).await?;
                                    }
                                    Err(err) => {
                                        let details = format!("{err:#}");
                                        error!(error = %details, "failed to apply firewall policy");
                                        client.report_heartbeat(&node_id, &interface, applied_version.max(0), "error", Some(&details)).await?;
                                        tokio::time::sleep(reconnect_delay).await;
                                        break;
                                    }
                                }
                            } else {
                                info!(
                                    enabled = drop_monitor_enabled,
                                    "applied xDS drop monitor setting"
                                );
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
                    log_xdp_stats(&xdp);
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

fn reconcile_drop_monitor(
    xdp: &mut xdp::XdpManager,
    handle: &mut Option<tokio::task::JoinHandle<()>>,
    enabled: bool,
    args: &AgentArgs,
    node_id: &str,
    interface: &str,
) -> Result<()> {
    if enabled && handle.is_none() {
        if let Err(err) = xdp.set_drop_monitor_enabled(true) {
            warn!(
                error = %err,
                "failed to enable XDP drop monitor; enforcement continues without drop event reporting"
            );
            return Ok(());
        }
        let events_path = match xdp::drop_events_pin_path(interface) {
            Ok(path) => path,
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to resolve XDP drop event pin path; enforcement continues without drop event reporting"
                );
                return Ok(());
            }
        };
        let client_config = xds::XdsClientConfig {
            control_url: args.control_url.clone(),
            agent_token: args.agent_token.clone(),
        };
        let node_id = node_id.to_string();
        let interface = interface.to_string();
        *handle = Some(tokio::spawn(async move {
            loop {
                match xds::XdsClient::connect(client_config.clone()).await {
                    Ok(mut client) => {
                        let events = match monitor::spawn_drop_event_reader(events_path.clone()) {
                            Ok(events) => events,
                            Err(err) => {
                                error!(
                                    error = %err,
                                    "failed to open XDP drop event reader; reconnecting"
                                );
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                        };
                        if let Err(err) = client
                            .report_drop_events(node_id.clone(), interface.clone(), events)
                            .await
                        {
                            error!(error = %err, "failed to report xDS drop events; reconnecting");
                        }
                    }
                    Err(err) => {
                        error!(error = %err, "failed to connect xDS for drop events; reconnecting");
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }));
        info!("enabled xDS drop monitor reporting");
    } else if !enabled && let Some(task) = handle.take() {
        task.abort();
        if let Err(err) = xdp.set_drop_monitor_enabled(false) {
            warn!(
                error = %err,
                "failed to disable XDP drop monitor; enforcement continues"
            );
        }
        info!("disabled xDS drop monitor reporting");
    }
    Ok(())
}

fn log_xdp_stats(xdp: &xdp::XdpManager) {
    match xdp.stats() {
        Ok(stats) => {
            debug!(
                pass = stats.pass,
                drop_total = stats.total_drop(),
                rule_drop = stats.rule_drop,
                geo_drop = stats.geo_drop,
                rate_drop = stats.rate_drop,
                flood_drop = stats.flood_drop,
                custom_rate_drop = stats.custom_rate_drop,
                temp_ban_drop = stats.temp_ban_drop,
                parse_drop = stats.parse_drop,
                "xdp stats"
            );
        }
        Err(err) => {
            error!(error = %err, "failed to read xdp stats");
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
        custom_rate_limit_entries: args.custom_rate_limit_map_entries,
        temp_ban_entries: args.temp_ban_map_entries,
    }
}

fn xdp_attach_options_for_agent(args: &AgentArgs) -> xdp::XdpAttachOptions {
    xdp::XdpAttachOptions {
        mode: args.xdp_mode,
        strategy: args.xdp_attach_strategy,
        allow_replace: args.xdp_allow_replace,
        auto_resize_maps: args.auto_resize_maps,
        run_priority: args.xdp_run_priority,
        loader_path: args.xdp_loader_path.clone(),
        bpftool_path: args.bpftool_path.clone(),
    }
}

fn sync_once_map_sizes(args: &SyncOnceArgs) -> xdp::XdpMapSizes {
    xdp::XdpMapSizes {
        rule_entries: args.rule_map_entries,
        geo_entries: args.geo_map_entries,
        trusted_entries: args.trusted_map_entries,
        country_entries: args.country_map_entries,
        rate_entries: args.rate_map_entries,
        custom_rate_limit_entries: args.custom_rate_limit_map_entries,
        temp_ban_entries: args.temp_ban_map_entries,
    }
}

fn xdp_attach_options_for_sync_once(args: &SyncOnceArgs) -> xdp::XdpAttachOptions {
    xdp::XdpAttachOptions {
        mode: args.xdp_mode,
        strategy: args.xdp_attach_strategy,
        allow_replace: args.xdp_allow_replace,
        auto_resize_maps: args.auto_resize_maps,
        run_priority: args.xdp_run_priority,
        loader_path: args.xdp_loader_path.clone(),
        bpftool_path: args.bpftool_path.clone(),
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
    add_control_plane_trusted_cidrs(&mut snapshot, control_url)?;
    log_policy_snapshot_summary(policy, expected_version, &snapshot);
    let compiled = firewall::compile_policy(&snapshot).await?;
    log_compiled_policy_summary(policy, expected_version, &compiled);
    xdp.apply(&compiled)?;
    info!(
        policy,
        expected_version,
        applied_version = compiled.version,
        "applied firewall policy"
    );
    Ok(compiled.version)
}

fn log_policy_snapshot_summary(
    policy: &str,
    expected_version: i64,
    snapshot: &firewall::PolicySnapshot,
) {
    let dynamic = &snapshot.dynamic_defense;
    info!(
        policy,
        expected_version,
        rules = snapshot.rules.len(),
        geo_countries = snapshot.geo_countries.len(),
        trusted_cidrs = snapshot.trusted_cidrs.len(),
        temp_bans = snapshot.temp_bans.len(),
        threat_sources = snapshot.threat_sources.len(),
        dynamic_rate_limits = snapshot.dynamic_rate_limits.len(),
        dynamic_defense_enabled = dynamic.enabled,
        ip_rate_limit_enabled = dynamic.ip_rate_limit_enabled,
        ip_packets_per_second = dynamic.ip_packets_per_second,
        ip_burst = dynamic.ip_burst,
        flood_enabled = dynamic.flood_enabled,
        flood_packets_per_second = dynamic.flood_packets_per_second,
        flood_burst = dynamic.flood_burst,
        flood_block_seconds = dynamic.flood_block_seconds,
        "received xDS policy snapshot"
    );
}

fn log_compiled_policy_summary(
    policy: &str,
    expected_version: i64,
    compiled: &firewall::CompiledPolicy,
) {
    info!(
        policy,
        expected_version,
        compiled_version = compiled.version,
        rule_prefixes = compiled.rules.len(),
        geo_prefixes = compiled.geo_prefixes.len(),
        country_rules = compiled.country_rules.len(),
        trusted_prefixes = compiled.trusted_prefixes.len(),
        temp_bans = compiled.temp_bans.len(),
        threat_prefixes = compiled.threat_prefixes.len(),
        dynamic_rate_limits = compiled.dynamic_rate_limits.len(),
        "compiled xDS policy for XDP maps"
    );
}

fn add_control_plane_trusted_cidrs(
    snapshot: &mut firewall::PolicySnapshot,
    control_url: &str,
) -> Result<()> {
    let prefixes = resolve_control_plane_prefixes(control_url)?;
    for cidr in prefixes {
        if snapshot
            .trusted_cidrs
            .iter()
            .any(|trusted| trusted.cidr == cidr)
        {
            continue;
        }
        snapshot.trusted_cidrs.push(firewall::TrustedCidrPolicy {
            cidr,
            comment: Some("local xDS control-plane allow".to_string()),
        });
    }
    Ok(())
}

fn resolve_control_plane_prefixes(control_url: &str) -> Result<Vec<IpNet>> {
    let (host, _) = control_plane_host_port(control_url)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        return Ok(vec![IpNet::new(ip, prefix).with_context(|| {
            format!("failed to build xDS control-plane CIDR for {ip}")
        })?]);
    }
    warn!(
        host,
        "xDS control URL host is not an IP literal; skipping automatic local control-plane allow to avoid DNS-based bypass"
    );
    Ok(Vec::new())
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
