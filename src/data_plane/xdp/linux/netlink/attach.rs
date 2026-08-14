use super::{DirectNetlinkLink, programs::current_xdp_program_id};
use crate::data_plane::xdp::{Result, XdpAttachMode};
use anyhow::{Context, bail};
use aya::programs::{Xdp, XdpMode};
use tracing::info;

mod replace;

use replace::direct_replace_program;

pub(in crate::data_plane::xdp::linux) fn attach_program(
    program: &mut Xdp,
    interface: &str,
    attach_mode: XdpAttachMode,
    allow_replace: bool,
    bpftool_path: &str,
) -> Result<Option<DirectNetlinkLink>> {
    match attach_mode {
        XdpAttachMode::Auto => attach_program_auto(program, interface, allow_replace, bpftool_path),
        XdpAttachMode::Driver => {
            let link = attach_program_mode(
                program,
                interface,
                XdpAttachMode::Driver,
                allow_replace,
                bpftool_path,
            )
            .context("failed to attach XDP program in driver mode")?;
            info!(interface, mode = "driver", "XDP program attached");
            Ok(link)
        }
        XdpAttachMode::Skb => {
            let link = attach_program_mode(
                program,
                interface,
                XdpAttachMode::Skb,
                allow_replace,
                bpftool_path,
            )
            .context("failed to attach XDP program in skb mode")?;
            info!(interface, mode = "skb", "XDP program attached");
            Ok(link)
        }
    }
}

fn attach_program_auto(
    program: &mut Xdp,
    interface: &str,
    allow_replace: bool,
    bpftool_path: &str,
) -> Result<Option<DirectNetlinkLink>> {
    match attach_program_mode(
        program,
        interface,
        XdpAttachMode::Driver,
        allow_replace,
        bpftool_path,
    ) {
        Ok(link) => {
            info!(interface, mode = "driver", "XDP program attached");
            Ok(link)
        }
        Err(driver_err) => {
            info!(
                interface,
                error = %driver_err,
                "driver XDP attach unavailable; using skb mode"
            );
            let link = attach_program_mode(
                program,
                interface,
                XdpAttachMode::Skb,
                allow_replace,
                bpftool_path,
            )
            .with_context(|| {
                format!("driver XDP attach failed ({driver_err:#}); skb attach failed")
            })?;
            info!(interface, mode = "skb", "XDP program attached");
            Ok(link)
        }
    }
}

fn attach_program_mode(
    program: &mut Xdp,
    interface: &str,
    mode: XdpAttachMode,
    allow_replace: bool,
    bpftool_path: &str,
) -> Result<Option<DirectNetlinkLink>> {
    let Some(existing_id) = current_xdp_program_id(interface, mode)? else {
        program.attach(interface, xdp_mode(mode))?;
        return Ok(None);
    };
    if !allow_replace {
        bail!(
            "interface '{interface}' already has an XDP program id {existing_id} in {} mode",
            mode.as_str()
        );
    }
    direct_replace_program(program, interface, mode, bpftool_path, existing_id)
}

fn xdp_mode(mode: XdpAttachMode) -> XdpMode {
    match mode {
        XdpAttachMode::Auto => XdpMode::Default,
        XdpAttachMode::Driver => XdpMode::Driver,
        XdpAttachMode::Skb => XdpMode::Skb,
    }
}
