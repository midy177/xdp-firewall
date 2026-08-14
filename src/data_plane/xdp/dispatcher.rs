use crate::cli::{XdpReplaceArgs, XdpStatusArgs, XdpTempBansArgs, XdpUnloadArgs};
use anyhow::{Result, bail};
use std::path::PathBuf;

pub fn drop_events_pin_path(interface: &str) -> Result<PathBuf> {
    Ok(map_pin_dir(interface)?.join("drop_events"))
}

pub fn drop_config_pin_path(interface: &str) -> Result<PathBuf> {
    Ok(map_pin_dir(interface)?.join("drop_config"))
}

pub fn map_pin_dir(interface: &str) -> Result<PathBuf> {
    Ok(PathBuf::from("/sys/fs/bpf/xdp-firewall").join(sanitize_pin_component(interface)?))
}

pub fn existing_xdp_summary(interface: &str) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        return super::linux::existing_xdp_summary(interface);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        Ok(None)
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn dispatcher_status(args: XdpStatusArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return super::linux::dispatcher_status(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp status is only supported on Linux")
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn dispatcher_temp_bans(args: XdpTempBansArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return super::linux::dispatcher_temp_bans(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp temp-bans is only supported on Linux");
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn dispatcher_unload(args: XdpUnloadArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return super::linux::dispatcher_unload(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp unload is only supported on Linux")
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn dispatcher_replace(args: XdpReplaceArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return super::linux::dispatcher_replace(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp replace is only supported on Linux")
    }
}

pub(super) fn sanitize_pin_component(value: &str) -> Result<String> {
    let sanitized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        bail!("interface name '{value}' is not safe for bpffs pin path");
    }
    Ok(sanitized)
}

#[cfg(test)]
mod tests;
