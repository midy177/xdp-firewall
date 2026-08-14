use crate::data_plane::xdp::{Result, XdpAttachMode};
use anyhow::{Context, bail};
use aya::programs::{ProgramFd, ProgramInfo};
use std::path::{Path, PathBuf};
use tracing::warn;

mod inspect;

use inspect::find_xdp_program_id;

struct TemporaryBpffsPin {
    path: PathBuf,
}

impl Drop for TemporaryBpffsPin {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                path = %self.path.display(),
                error = %err,
                "failed to remove temporary bpffs pin"
            );
        }
    }
}

pub(super) fn program_fd_by_id(
    bpftool_path: &str,
    interface: &str,
    program_id: u32,
) -> Result<ProgramFd> {
    let safe_interface = crate::data_plane::xdp::dispatcher::sanitize_pin_component(interface)?;
    let pin_root = Path::new("/sys/fs/bpf/xdp-firewall");
    std::fs::create_dir_all(pin_root)
        .with_context(|| format!("failed to create bpffs pin root '{}'", pin_root.display()))?;
    let pin_path = pin_root.join(format!(
        ".direct-replace-old-{safe_interface}-{}-{program_id}",
        std::process::id()
    ));
    if pin_path.exists() {
        std::fs::remove_file(&pin_path).with_context(|| {
            format!(
                "failed to remove stale temporary bpffs pin '{}'",
                pin_path.display()
            )
        })?;
    }
    let output = std::process::Command::new(bpftool_path)
        .args(["prog", "pin", "id"])
        .arg(program_id.to_string())
        .arg(&pin_path)
        .output()
        .with_context(|| format!("failed to run '{bpftool_path} prog pin'"))?;
    if !output.status.success() {
        bail!(
            "bpftool failed to pin existing XDP program id {program_id}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _pin = TemporaryBpffsPin {
        path: pin_path.clone(),
    };
    ProgramInfo::from_pin(&pin_path)
        .with_context(|| {
            format!(
                "failed to open temporary bpffs pin '{}' for existing XDP program id {program_id}",
                pin_path.display()
            )
        })?
        .fd()
        .context("failed to clone fd from temporary bpffs pin")
}

pub(super) fn current_xdp_program_id(interface: &str, mode: XdpAttachMode) -> Result<Option<u32>> {
    let output = std::process::Command::new("ip")
        .args(["-j", "-details", "link", "show", "dev", interface])
        .output()
        .with_context(|| format!("failed to inspect interface '{interface}' with ip"))?;
    if !output.status.success() {
        bail!(
            "failed to inspect interface '{interface}' for XDP program id: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let value = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .context("failed to parse ip JSON while detecting current XDP program id")?;
    Ok(find_xdp_program_id(&value, mode))
}
