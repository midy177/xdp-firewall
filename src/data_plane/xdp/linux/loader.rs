use super::*;
use tracing::warn;

mod command;
mod load;
mod map_identity;
mod programs;
mod unload;

pub(super) use command::{
    ensure_success, is_no_dispatcher_output, print_command_output, run_xdp_loader_command,
    xdp_loader_verbose_args,
};
pub(super) use load::run_xdp_loader_load;
pub(super) use map_identity::verify_dispatcher_map_identity;
pub(super) use programs::{dispatcher_program_ids_by_name, unload_dispatcher_programs_by_name};
pub(super) use unload::{dispatcher_unload_inner, remove_map_pin_dir};

pub(super) fn require_explicit_interface(
    configured: Option<&str>,
    message: &str,
) -> Result<String> {
    let Some(interface) = configured.map(str::trim).filter(|value| !value.is_empty()) else {
        bail!("{message}");
    };
    resolve_interface_name(Some(interface))
}

pub(super) fn rollback_failed_attach(
    interface: &str,
    program_name: &str,
    attach_options: &XdpAttachOptions,
    pin_dir: &Path,
    pin_dir_existed: bool,
    dispatcher_loaded: bool,
) {
    if dispatcher_loaded {
        if let Err(err) = unload_dispatcher_programs_by_name(
            &attach_options.loader_path,
            interface,
            program_name,
            true,
        ) {
            warn!(
                interface,
                program = program_name,
                error = %err,
                "failed to roll back dispatcher program after attach failure"
            );
        }
    }
    if !pin_dir_existed {
        match std::fs::remove_dir_all(pin_dir) {
            Ok(()) => {
                debug!(pin_dir = %pin_dir.display(), "removed pin directory after attach failure");
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(
                    pin_dir = %pin_dir.display(),
                    error = %err,
                    "failed to remove pin directory after attach failure"
                );
            }
        }
    }
}

pub(super) fn ensure_no_existing_xdp(interface: &str) -> Result<()> {
    if let Some(existing) = existing_xdp_summary(interface)? {
        bail!(
            "interface '{interface}' already has an XDP program attached ({existing}); refusing to replace it in direct mode. Use --xdp-allow-replace to replace intentionally, or use --xdp-attach-strategy dispatcher to join the libxdp multiprogram chain"
        );
    }
    Ok(())
}
