use super::*;

pub(in crate::data_plane::xdp::linux) fn dispatcher_unload_inner(
    interface: &str,
    loader_path: &str,
    program_id: Option<u32>,
    all: bool,
    remove_pins: bool,
    clean: bool,
    verbose: u8,
    tolerate_missing: bool,
) -> Result<()> {
    validate_unload_request(program_id, all, remove_pins)?;
    run_xdp_loader_unload(
        interface,
        loader_path,
        program_id,
        all,
        verbose,
        tolerate_missing,
    )?;
    if clean {
        run_xdp_loader_clean(interface, loader_path, verbose)?;
    }
    if remove_pins {
        remove_map_pin_dir(interface)?;
    }
    println!("dispatcher unload completed interface={interface}");
    Ok(())
}

pub(in crate::data_plane::xdp::linux) fn remove_map_pin_dir(interface: &str) -> Result<()> {
    let pin_dir = map_pin_dir(interface)?;
    match std::fs::remove_dir_all(&pin_dir) {
        Ok(()) => {
            println!("removed pinned map directory {}", pin_dir.display());
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to remove pinned map directory '{}'",
                pin_dir.display()
            )
        }),
    }
}

fn validate_unload_request(program_id: Option<u32>, all: bool, remove_pins: bool) -> Result<()> {
    if !all && program_id.is_none() {
        bail!("xdp unload/replace requires either --all or --id <program-id>");
    }
    if remove_pins && !all {
        bail!(
            "--remove-pins requires --all so pinned maps are not removed while another dispatcher program may still use them"
        );
    }
    Ok(())
}

fn run_xdp_loader_unload(
    interface: &str,
    loader_path: &str,
    program_id: Option<u32>,
    all: bool,
    verbose: u8,
    tolerate_missing: bool,
) -> Result<()> {
    let mut args = xdp_loader_verbose_args(verbose, ["unload"]);
    if all {
        args.push("--all".to_string());
    } else if let Some(id) = program_id {
        args.push("--id".to_string());
        args.push(id.to_string());
    }
    args.push(interface.to_string());
    let output = run_xdp_loader_command(loader_path, args)
        .with_context(|| format!("failed to run xdp-loader unload for '{interface}'"))?;
    print_command_output(&output);
    match ensure_success("xdp-loader unload", &output) {
        Ok(()) => Ok(()),
        Err(err) if tolerate_missing && is_no_dispatcher_output(&output) => {
            debug!(
                interface,
                error = %err,
                "dispatcher unload found no matching program; continuing"
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn run_xdp_loader_clean(interface: &str, loader_path: &str, verbose: u8) -> Result<()> {
    let mut clean_args = xdp_loader_verbose_args(verbose, ["clean"]);
    clean_args.push(interface.to_string());
    let clean_output = run_xdp_loader_command(loader_path, clean_args)
        .with_context(|| format!("failed to run xdp-loader clean for '{interface}'"))?;
    print_command_output(&clean_output);
    ensure_success("xdp-loader clean", &clean_output)
}
