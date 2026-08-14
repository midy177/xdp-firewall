use super::config::resolve_node_id;
use crate::cli::MonitorArgs;
use crate::data_plane::xdp;
use anyhow::{Result, bail};
use serde::Serialize;
use tokio::time::{Duration, sleep};

mod drop_events;
mod host;
mod xds_sample;

#[cfg(target_os = "linux")]
pub use drop_events::parse_drop_event;
pub use drop_events::{DropEventLine, DropEventReader, spawn_drop_event_reader};

use host::HostSnapshot;
use xds_sample::{XdsMonitorSample, sample_xds};

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
    let events_path = args.drop_events_path.clone().map_or_else(
        || xdp::drop_events_pin_path(&interface),
        |path| Ok(std::path::PathBuf::from(path)),
    )?;
    let config_path = xdp::drop_config_pin_path(&interface)?;
    drop_events::stream(events_path, Some(config_path), args.json).await
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
                    .map_or_else(|| "unknown".to_string(), |value| value.to_string())
            ),
            format!("xds_status={}", self.xds.status),
        ];
        if let Some(details) = self.xds.details.as_deref() {
            fields.push(details.to_string());
        }
        fields.join(" ")
    }
}

pub(super) fn public_error(error: &anyhow::Error) -> String {
    error
        .to_string()
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_value(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/' | b'=')
    }) {
        return value.to_string();
    }
    serde_json::to_string(value).unwrap_or_else(|_| "\"<invalid>\"".to_string())
}
