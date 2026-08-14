use crate::data_plane::xdp;
use serde::Serialize;

use super::public_error;

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct HostSnapshot {
    pub(super) operstate: Option<String>,
    pub(super) mtu: Option<String>,
    pub(super) carrier: Option<String>,
    pub(super) xdp_attached: bool,
    pub(super) xdp_summary: Option<String>,
    pub(super) bpffs_mounted: bool,
    pub(super) agent_only: bool,
    pub(super) database_url_present: bool,
    pub(super) local_db_file_present: bool,
    pub(super) xdp_firewall_processes: Option<usize>,
}

impl HostSnapshot {
    pub(super) fn load(interface: &str) -> Self {
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
