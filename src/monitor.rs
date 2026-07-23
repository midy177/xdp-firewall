use crate::cli::MonitorArgs;
use crate::{firewall, xdp, xds};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::time::{Duration, sleep};

pub async fn run(args: MonitorArgs) -> Result<()> {
    if args.interval_seconds == 0 {
        bail!("interval-seconds must be greater than 0");
    }

    loop {
        let sample = collect_sample(&args).await;
        if args.json {
            println!("{}", serde_json::to_string(&sample)?);
        } else {
            println!("{}", sample.to_line());
        }
        if args.once {
            return Ok(());
        }
        sleep(Duration::from_secs(args.interval_seconds)).await;
    }
}

async fn collect_sample(args: &MonitorArgs) -> MonitorSample {
    let sampled_at = chrono::Utc::now().to_rfc3339();
    let node_id = resolve_node_id(args.node_id.as_deref())
        .unwrap_or_else(|err| format!("unknown ({})", public_error(&err)));
    let interface = xdp::resolve_interface_name(args.interface.as_deref())
        .unwrap_or_else(|err| format!("unknown ({})", public_error(&err)));
    let host = HostSnapshot::load(&interface);
    let xds = sample_xds(args, &node_id, &interface).await;

    MonitorSample {
        time: sampled_at,
        node_id,
        interface,
        control_url: args.control_url.clone(),
        host,
        xds,
    }
}

#[derive(Debug, Serialize)]
struct MonitorSample {
    time: String,
    node_id: String,
    interface: String,
    control_url: String,
    host: HostSnapshot,
    xds: XdsMonitorSample,
}

impl MonitorSample {
    fn to_line(&self) -> String {
        let mut fields = vec![
            format!("time={}", self.time),
            format!("node_id={}", self.node_id),
            format!("interface={}", self.interface),
            format!("control_url={}", self.control_url),
            format!(
                "operstate={}",
                self.host.operstate.as_deref().unwrap_or("unknown")
            ),
            format!("mtu={}", self.host.mtu.as_deref().unwrap_or("unknown")),
            format!(
                "carrier={}",
                self.host.carrier.as_deref().unwrap_or("unknown")
            ),
            format!("bpffs_mounted={}", self.host.bpffs_mounted),
            format!("agent_only={}", self.host.agent_only),
            format!("database_url_present={}", self.host.database_url_present),
            format!("local_db_file_present={}", self.host.local_db_file_present),
            format!(
                "agent_processes={}",
                self.host
                    .agent_processes
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            format!("xds_status={}", self.xds.status),
        ];
        if let Some(details) = self.xds.details.as_deref() {
            fields.push(details.to_string());
        }
        fields.join(" ")
    }
}

async fn sample_xds(args: &MonitorArgs, node_id: &str, interface: &str) -> XdsMonitorSample {
    let mut client = match xds::XdsClient::connect(xds::XdsClientConfig {
        control_url: args.control_url.clone(),
        agent_token: args.agent_token.clone(),
    })
    .await
    {
        Ok(client) => client,
        Err(err) => {
            return XdsMonitorSample::error(format!("error={}", public_error(&err)));
        }
    };

    match client.fetch_policy(node_id, interface, -1).await {
        Ok(Some((version, snapshot))) => XdsMonitorSample::policy(version, &snapshot),
        Ok(None) => XdsMonitorSample {
            status: "ok".to_string(),
            details: Some("policy=unchanged".to_string()),
            policy: None,
        },
        Err(err) => XdsMonitorSample::error(public_error(&err)),
    }
}

#[derive(Debug, Serialize)]
struct XdsMonitorSample {
    status: String,
    details: Option<String>,
    policy: Option<PolicyMonitorSample>,
}

impl XdsMonitorSample {
    fn policy(version: i64, snapshot: &firewall::PolicySnapshot) -> Self {
        let dynamic = &snapshot.dynamic_defense;
        Self {
            status: "ok".to_string(),
            details: Some(format!(
                "policy_version={} rules={} geo_countries={} trusted_cidrs={} threat_sources={} dynamic_defense={} ip_rate_limit={} flood={}",
                version,
                snapshot.rules.len(),
                snapshot.geo_countries.len(),
                snapshot.trusted_cidrs.len(),
                snapshot.threat_sources.len(),
                dynamic.enabled,
                dynamic.ip_rate_limit_enabled,
                dynamic.flood_enabled
            )),
            policy: Some(PolicyMonitorSample {
                version,
                rules: snapshot.rules.len(),
                geo_countries: snapshot.geo_countries.len(),
                trusted_cidrs: snapshot.trusted_cidrs.len(),
                threat_sources: snapshot.threat_sources.len(),
                dynamic_defense: dynamic.enabled,
                ip_rate_limit: dynamic.ip_rate_limit_enabled,
                flood: dynamic.flood_enabled,
            }),
        }
    }

    fn error(details: String) -> Self {
        Self {
            status: "error".to_string(),
            details: Some(details),
            policy: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct PolicyMonitorSample {
    version: i64,
    rules: usize,
    geo_countries: usize,
    trusted_cidrs: usize,
    threat_sources: usize,
    dynamic_defense: bool,
    ip_rate_limit: bool,
    flood: bool,
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

fn public_error(error: &anyhow::Error) -> String {
    error
        .to_string()
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Serialize)]
struct HostSnapshot {
    operstate: Option<String>,
    mtu: Option<String>,
    carrier: Option<String>,
    bpffs_mounted: bool,
    agent_only: bool,
    database_url_present: bool,
    local_db_file_present: bool,
    agent_processes: Option<usize>,
}

impl HostSnapshot {
    fn load(interface: &str) -> Self {
        Self {
            operstate: read_trimmed(format!("/sys/class/net/{interface}/operstate")),
            mtu: read_trimmed(format!("/sys/class/net/{interface}/mtu")),
            carrier: read_trimmed(format!("/sys/class/net/{interface}/carrier")),
            bpffs_mounted: bpffs_mounted(),
            agent_only: env_flag("XDP_FIREWALL_AGENT_ONLY"),
            database_url_present: std::env::var("DATABASE_URL")
                .ok()
                .is_some_and(|value| !value.trim().is_empty()),
            local_db_file_present: std::path::Path::new("/var/lib/xdp-firewall/xdp-firewall.db")
                .exists(),
            agent_processes: count_agent_processes(),
        }
    }
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn read_trimmed(path: impl AsRef<std::path::Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bpffs_mounted() -> bool {
    std::fs::read_to_string("/proc/mounts")
        .ok()
        .is_some_and(|mounts| {
            mounts.lines().any(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                fields.get(1) == Some(&"/sys/fs/bpf") && fields.get(2) == Some(&"bpf")
            })
        })
}

fn count_agent_processes() -> Option<usize> {
    let entries = std::fs::read_dir("/proc").ok()?;
    let mut count = 0_usize;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let command = String::from_utf8_lossy(&cmdline);
        if command.contains("xdp-firewall") && command.contains("agent") {
            count += 1;
        }
    }
    Some(count)
}
