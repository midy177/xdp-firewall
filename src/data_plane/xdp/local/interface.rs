use std::net::IpAddr;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::data_plane::xdp) struct LocalInterfaceCidr {
    pub(in crate::data_plane::xdp) ip: IpAddr,
    pub(in crate::data_plane::xdp) prefix: u8,
}

pub(in crate::data_plane::xdp) fn format_local_interface_cidrs(
    cidrs: &[LocalInterfaceCidr],
) -> String {
    cidrs
        .iter()
        .map(|cidr| format!("{}/{}", cidr.ip, cidr.prefix))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(target_os = "linux")]
pub(in crate::data_plane::xdp) fn local_interface_cidrs(
    interface: &str,
) -> Result<Vec<LocalInterfaceCidr>> {
    let output = std::process::Command::new("ip")
        .args(["-j", "addr", "show", "dev", interface])
        .output()
        .with_context(|| format!("failed to inspect interface '{interface}' addresses with ip"))?;
    if !output.status.success() {
        bail!(
            "failed to inspect interface '{interface}' addresses: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let value = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .context("failed to parse ip JSON while detecting interface addresses")?;
    let mut cidrs = Vec::new();
    collect_interface_cidrs_from_json(&value, &mut cidrs);
    cidrs.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then_with(|| left.prefix.cmp(&right.prefix))
    });
    cidrs.dedup();
    Ok(cidrs)
}

#[cfg(target_os = "linux")]
fn collect_interface_cidrs_from_json(
    value: &serde_json::Value,
    cidrs: &mut Vec<LocalInterfaceCidr>,
) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(addr_info) = object.get("addr_info") {
                collect_interface_cidrs_from_json(addr_info, cidrs);
            }
            if object
                .get("family")
                .and_then(|value| value.as_str())
                .is_some_and(|family| matches!(family, "inet" | "inet6"))
                && let Some(local) = object.get("local").and_then(|value| value.as_str())
                && let Ok(ip) = local.parse::<IpAddr>()
            {
                let prefix = object
                    .get("prefixlen")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u8::try_from(value).ok())
                    .unwrap_or_else(|| if ip.is_ipv4() { 32 } else { 128 });
                cidrs.push(LocalInterfaceCidr { ip, prefix });
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_interface_cidrs_from_json(value, cidrs);
            }
        }
        _ => {}
    }
}
