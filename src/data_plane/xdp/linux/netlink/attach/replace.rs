use super::super::{DirectNetlinkLink, message::set_xdp_fd, programs::program_fd_by_id};
use crate::data_plane::xdp::{Result, XdpAttachMode};
use anyhow::{Context, bail};
use aya::programs::Xdp;
use std::os::fd::AsFd;
use tracing::info;

pub(super) fn direct_replace_program(
    program: &mut Xdp,
    interface: &str,
    mode: XdpAttachMode,
    bpftool_path: &str,
    existing_id: u32,
) -> Result<Option<DirectNetlinkLink>> {
    let if_index = if_index(interface)?;
    let old_prog = program_fd_by_id(bpftool_path, interface, existing_id)
        .with_context(|| format!("failed to get fd for existing XDP program id {existing_id}"))?;
    let new_prog_fd = program
        .fd()
        .context("XDP program fd is not available after load")?
        .as_fd()
        .try_clone_to_owned()
        .context("failed to clone loaded XDP program fd for direct replacement tracking")?;
    set_xdp_fd(
        if_index,
        Some(new_prog_fd.as_fd()),
        Some(old_prog.as_fd()),
        mode,
    )
    .with_context(|| {
        format!(
            "failed to replace existing XDP program id {existing_id} on interface '{interface}' in {} mode",
            mode.as_str()
        )
    })?;
    info!(
        interface,
        mode = %mode.as_str(),
        replaced_program_id = existing_id,
        "replaced existing direct XDP program"
    );
    Ok(Some(DirectNetlinkLink {
        interface: interface.to_string(),
        if_index,
        prog_fd: new_prog_fd,
        mode,
    }))
}

fn if_index(interface: &str) -> Result<i32> {
    let c_interface = std::ffi::CString::new(interface)
        .with_context(|| format!("interface '{interface}' contains an embedded NUL"))?;
    let index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if index == 0 {
        bail!("interface '{interface}' does not exist");
    }
    i32::try_from(index).context("interface index is outside i32 range")
}
