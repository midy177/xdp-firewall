use anyhow::{Context, Result, bail};
use std::net::IpAddr;

pub(super) fn format_interface_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn validate_positive_arg(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        bail!("{name} must be greater than 0");
    }
    Ok(())
}

pub(super) fn sync_once_status() -> (&'static str, Option<String>) {
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

pub(super) fn resolve_node_id(configured: Option<&str>) -> Result<String> {
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
