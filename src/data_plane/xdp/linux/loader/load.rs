use super::*;

pub(in crate::data_plane::xdp::linux) fn run_xdp_loader_load(
    interface: &str,
    object_path: &str,
    program_name: &str,
    options: &XdpAttachOptions,
    pin_dir: &Path,
) -> Result<()> {
    match options.mode {
        XdpAttachMode::Auto => {
            load_auto_mode(interface, object_path, program_name, options, pin_dir)
        }
        XdpAttachMode::Driver => load_mode(
            interface,
            object_path,
            program_name,
            options,
            pin_dir,
            "native",
        ),
        XdpAttachMode::Skb => load_mode(
            interface,
            object_path,
            program_name,
            options,
            pin_dir,
            "skb",
        ),
    }
}

fn load_auto_mode(
    interface: &str,
    object_path: &str,
    program_name: &str,
    options: &XdpAttachOptions,
    pin_dir: &Path,
) -> Result<()> {
    if let Err(driver_err) = run_xdp_loader_load_mode(
        interface,
        object_path,
        program_name,
        options,
        pin_dir,
        "native",
    ) {
        info!(
            interface,
            error = %driver_err,
            "dispatcher native XDP attach unavailable; using skb mode"
        );
        run_xdp_loader_load_mode(
            interface,
            object_path,
            program_name,
            options,
            pin_dir,
            "skb",
        )
        .with_context(|| {
            format!("dispatcher native XDP attach failed ({driver_err:#}); skb attach failed")
        })?;
        info!(interface, mode = "skb", "XDP dispatcher program attached");
    } else {
        info!(
            interface,
            mode = "native",
            "XDP dispatcher program attached"
        );
    }
    Ok(())
}

fn load_mode(
    interface: &str,
    object_path: &str,
    program_name: &str,
    options: &XdpAttachOptions,
    pin_dir: &Path,
    mode: &str,
) -> Result<()> {
    run_xdp_loader_load_mode(interface, object_path, program_name, options, pin_dir, mode)?;
    info!(interface, mode, "XDP dispatcher program attached");
    Ok(())
}

fn run_xdp_loader_load_mode(
    interface: &str,
    object_path: &str,
    program_name: &str,
    options: &XdpAttachOptions,
    pin_dir: &Path,
    mode: &str,
) -> Result<()> {
    let pin_dir = pin_dir
        .to_str()
        .context("XDP map pin directory is not valid UTF-8")?;
    let priority = options.run_priority.to_string();
    let output = std::process::Command::new(&options.loader_path)
        .args([
            "load",
            "--mode",
            mode,
            "--pin-path",
            pin_dir,
            "--prog-name",
            program_name,
            "--prio",
            &priority,
            interface,
            object_path,
        ])
        .output()
        .with_context(|| {
            format!(
                "failed to execute xdp-loader '{}' for dispatcher attach",
                options.loader_path
            )
        })?;
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "xdp-loader dispatcher attach failed in {mode} mode: status={} stdout='{}' stderr='{}'",
        output.status,
        stdout.trim(),
        stderr.trim()
    );
}
