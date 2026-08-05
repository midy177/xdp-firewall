use crate::cli::MonitorArgs;
#[cfg(target_os = "linux")]
use crate::geo;
use crate::{firewall, xdp, xds};
use anyhow::{Context, Result, bail};
#[cfg(target_os = "linux")]
use aya::{
    maps::{Array as AyaArray, Map, MapData, PerfEventArray, perf::PerfEvent},
    util::online_cpus,
};
use serde::Serialize;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::time::{Duration, sleep};
use tokio::{sync::mpsc, task::JoinHandle};

pub async fn run(args: MonitorArgs) -> Result<()> {
    if args.r#drop {
        return stream_drop_events(args).await;
    }
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

async fn stream_drop_events(args: MonitorArgs) -> Result<()> {
    let interface = xdp::resolve_interface_name(args.interface.as_deref())
        .unwrap_or_else(|err| format!("unknown ({})", public_error(&err)));
    let events_path = args
        .drop_events_path
        .clone()
        .map(std::path::PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| xdp::drop_events_pin_path(&interface))?;
    let config_path = xdp::drop_config_pin_path(&interface)?;
    drop_monitor::stream(events_path, Some(config_path), args.json).await
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
            format!("xdp_attached={}", self.host.xdp_attached),
            format!(
                "xdp_summary={}",
                quote_value(self.host.xdp_summary.as_deref().unwrap_or("-"))
            ),
            format!("agent_only={}", self.host.agent_only),
            format!("database_url_present={}", self.host.database_url_present),
            format!("local_db_file_present={}", self.host.local_db_file_present),
            format!(
                "xdp_firewall_processes={}",
                self.host
                    .xdp_firewall_processes
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
                "policy_version={} rules={} geo_countries={} trusted_cidrs={} temp_bans={} threat_sources={} dynamic_rate_limits={} dynamic_defense={} ip_rate_limit={} flood={}",
                version,
                snapshot.rules.len(),
                snapshot.geo_countries.len(),
                snapshot.trusted_cidrs.len(),
                snapshot.temp_bans.len(),
                snapshot.threat_sources.len(),
                snapshot.dynamic_rate_limits.len(),
                dynamic.enabled,
                dynamic.ip_rate_limit_enabled,
                dynamic.flood_enabled
            )),
            policy: Some(PolicyMonitorSample {
                version,
                rules: snapshot.rules.len(),
                geo_countries: snapshot.geo_countries.len(),
                trusted_cidrs: snapshot.trusted_cidrs.len(),
                temp_bans: snapshot.temp_bans.len(),
                threat_sources: snapshot.threat_sources.len(),
                dynamic_rate_limits: snapshot.dynamic_rate_limits.len(),
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
    temp_bans: usize,
    threat_sources: usize,
    dynamic_rate_limits: usize,
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

#[derive(Debug, Clone, Serialize)]
pub struct DropEventLine {
    pub time: String,
    pub event_time_ns: u64,
    pub cpu: u32,
    pub reason: &'static str,
    pub src: IpAddr,
    pub family: u8,
    pub proto: String,
    pub dport: u16,
    pub country: Option<String>,
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_source: Option<String>,
}

pub struct DropEventReader {
    receiver: mpsc::Receiver<DropEventLine>,
    task: Option<JoinHandle<()>>,
}

impl DropEventReader {
    pub async fn recv(&mut self) -> Option<DropEventLine> {
        self.receiver.recv().await
    }
}

impl Drop for DropEventReader {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl DropEventLine {
    pub fn to_line(&self) -> String {
        let country = self.country.as_deref().unwrap_or("-");
        format!(
            "time={} event_time_ns={} cpu={} reason={} src={} family={} proto={} dport={} country={} action={}{}",
            self.time,
            self.event_time_ns,
            self.cpu,
            self.reason,
            self.src,
            self.family,
            self.proto,
            self.dport,
            country,
            self.action,
            self.threat_source
                .as_deref()
                .map(|source| format!(" threat_source={source}"))
                .unwrap_or_default()
        )
    }
}

#[cfg(target_os = "linux")]
pub fn parse_drop_event(cpu: u32, bytes: &[u8]) -> Option<DropEventLine> {
    if bytes.len() < 36 {
        return None;
    }
    let event_time_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let reason = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let family = bytes[12];
    let proto = bytes[13];
    let dport = u16::from_be_bytes(bytes[14..16].try_into().ok()?);
    let mut addr = [0_u8; 16];
    addr.copy_from_slice(&bytes[16..32]);
    let country = u16::from_ne_bytes(bytes[32..34].try_into().ok()?);
    let action = bytes[34];
    let source = bytes[35];
    let src = match family {
        4 => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
        6 => IpAddr::V6(Ipv6Addr::from(addr)),
        _ => return None,
    };
    Some(DropEventLine {
        time: chrono::Utc::now().to_rfc3339(),
        event_time_ns,
        cpu,
        reason: reason_label(reason, source),
        src,
        family,
        proto: proto_label(proto).to_string(),
        dport,
        country: decode_country(country),
        action: action_label(action),
        threat_source: None,
    })
}

#[cfg(target_os = "linux")]
fn reason_label(reason: u32, source: u8) -> &'static str {
    match reason {
        xdp::STAT_RULE_DROP if source == 2 => "threat_intel",
        xdp::STAT_RULE_DROP => "firewall_rule",
        xdp::STAT_GEO_DROP => "country",
        xdp::STAT_TEMP_BAN_DROP => "temporary_ban",
        xdp::STAT_RATE_DROP => "dynamic_defense.ip_rate_limit",
        xdp::STAT_FLOOD_DROP => "dynamic_defense.flood",
        xdp::STAT_CUSTOM_RATE_DROP => "dynamic_defense.custom_rate_limit",
        xdp::STAT_PARSE_DROP => "parse_error",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn proto_label(proto: u8) -> &'static str {
    match proto {
        0 => "any",
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

#[cfg(target_os = "linux")]
fn action_label(action: u8) -> &'static str {
    match action {
        1 => "allow",
        2 => "deny",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn decode_country(country: u16) -> Option<String> {
    if country == 0 {
        return None;
    }
    let first = ((country >> 8) & 0xff) as u8;
    let second = (country & 0xff) as u8;
    let code = String::from_utf8(vec![first, second]).ok()?;
    geo::normalize_country(&code).ok()
}

#[cfg(target_os = "linux")]
mod drop_monitor {
    use super::*;

    pub fn spawn_reader(path: std::path::PathBuf) -> Result<DropEventReader> {
        open_reader(path)
    }

    pub async fn stream(
        events_path: std::path::PathBuf,
        config_path: Option<std::path::PathBuf>,
        json: bool,
    ) -> Result<()> {
        let mut config = if let Some(path) = config_path {
            Some(open_drop_config(&path)?)
        } else {
            None
        };
        if let Some(config) = config.as_mut() {
            set_drop_config(config, true)?;
        }
        let result = print_events(events_path, json).await;
        if let Some(config) = config.as_mut() {
            let _ = set_drop_config(config, false);
        }
        result
    }

    async fn print_events(path: std::path::PathBuf, json: bool) -> Result<()> {
        let mut reader = open_reader(path)?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to register SIGTERM handler")?;
        loop {
            tokio::select! {
                event = reader.recv() => {
                    let Some(line) = event else {
                        return Ok(());
                    };
                    if json {
                        match serde_json::to_string(&line) {
                            Ok(value) => println!("{value}"),
                            Err(err) => eprintln!("failed to serialize drop event: {err}"),
                        }
                    } else {
                        println!("{}", line.to_line());
                    }
                }
                result = tokio::signal::ctrl_c() => {
                    result?;
                    return Ok(());
                }
                _ = terminate.recv() => {
                    return Ok(());
                }
            }
        }
    }

    fn open_reader(path: std::path::PathBuf) -> Result<DropEventReader> {
        let map_data = MapData::from_pin(&path).with_context(|| {
            format!(
                "failed to open pinned drop_events map '{}'; start a new agent first",
                path.display()
            )
        })?;
        let map = Map::from_map_data(map_data)
            .context("pinned drop_events path is not a supported BPF map")?;
        let mut events: PerfEventArray<MapData> = map
            .try_into()
            .context("pinned drop_events map has unexpected type")?;
        let cpus = online_cpus().map_err(|(_, err)| err)?;
        let mut buffers = Vec::new();
        for cpu in cpus {
            let buffer = events
                .open(cpu, Some(16))
                .with_context(|| format!("failed to open drop event perf buffer for CPU {cpu}"))?;
            buffers.push((cpu, buffer));
        }
        let (tx, rx) = mpsc::channel(1024);
        let task = tokio::spawn(async move {
            loop {
                if tx.is_closed() {
                    break;
                }
                let mut drained = false;
                for (cpu, buffer) in &mut buffers {
                    if !buffer.readable() {
                        continue;
                    }
                    drained = true;
                    buffer.for_each(|event| match event {
                        PerfEvent::Sample { head, tail } => {
                            let mut bytes = Vec::with_capacity(head.len() + tail.len());
                            bytes.extend_from_slice(head);
                            bytes.extend_from_slice(tail);
                            if let Some(line) = parse_drop_event(*cpu, &bytes) {
                                let _ = tx.try_send(line);
                            }
                        }
                        PerfEvent::Lost { count } => {
                            eprintln!("lost {count} drop events on CPU {cpu}");
                        }
                    });
                }
                if !drained {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        });
        Ok(DropEventReader {
            receiver: rx,
            task: Some(task),
        })
    }

    fn open_drop_config(path: &std::path::Path) -> Result<AyaArray<MapData, u8>> {
        let map_data = MapData::from_pin(path).with_context(|| {
            format!(
                "failed to open pinned drop_config map '{}'; start a new agent first",
                path.display()
            )
        })?;
        Map::from_map_data(map_data)
            .context("pinned drop_config path is not a supported BPF map")?
            .try_into()
            .context("pinned drop_config map has unexpected type")
    }

    fn set_drop_config(config: &mut AyaArray<MapData, u8>, enabled: bool) -> Result<()> {
        config.set(0, u8::from(enabled), 0)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn spawn_drop_event_reader(path: std::path::PathBuf) -> Result<DropEventReader> {
    drop_monitor::spawn_reader(path)
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_drop_event_reader(_path: std::path::PathBuf) -> Result<DropEventReader> {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    Ok(DropEventReader {
        receiver: rx,
        task: None,
    })
}

#[cfg(not(target_os = "linux"))]
mod drop_monitor {
    use super::*;

    pub async fn stream(
        events_path: std::path::PathBuf,
        config_path: Option<std::path::PathBuf>,
        json: bool,
    ) -> Result<()> {
        let _ = (events_path, config_path, json);
        bail!("monitor --drop is only supported on Linux")
    }
}

#[derive(Debug, Serialize)]
struct HostSnapshot {
    operstate: Option<String>,
    mtu: Option<String>,
    carrier: Option<String>,
    xdp_attached: bool,
    xdp_summary: Option<String>,
    bpffs_mounted: bool,
    agent_only: bool,
    database_url_present: bool,
    local_db_file_present: bool,
    xdp_firewall_processes: Option<usize>,
}

impl HostSnapshot {
    fn load(interface: &str) -> Self {
        let (xdp_attached, xdp_summary) = match xdp::existing_xdp_summary(interface) {
            Ok(summary) => (summary.is_some(), summary),
            Err(err) => (false, Some(format!("unknown ({})", public_error(&err)))),
        };
        Self {
            operstate: read_trimmed(format!("/sys/class/net/{interface}/operstate")),
            mtu: read_trimmed(format!("/sys/class/net/{interface}/mtu")),
            carrier: read_trimmed(format!("/sys/class/net/{interface}/carrier")),
            xdp_attached,
            xdp_summary,
            bpffs_mounted: bpffs_mounted(),
            agent_only: env_flag("XDP_FIREWALL_AGENT_ONLY"),
            database_url_present: std::env::var("DATABASE_URL")
                .ok()
                .is_some_and(|value| !value.trim().is_empty()),
            local_db_file_present: std::path::Path::new("/var/lib/xdp-firewall/xdp-firewall.db")
                .exists(),
            xdp_firewall_processes: count_xdp_firewall_processes(),
        }
    }
}

fn quote_value(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/' | b'=')
    }) {
        return value.to_string();
    }
    serde_json::to_string(value).unwrap_or_else(|_| "\"<invalid>\"".to_string())
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

fn count_xdp_firewall_processes() -> Option<usize> {
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
        if command.contains("xdp-firewall") {
            count += 1;
        }
    }
    Some(count)
}
