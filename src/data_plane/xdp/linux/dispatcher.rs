use super::*;
use crate::cli::{XdpReplaceArgs, XdpStatusArgs, XdpUnloadArgs};

mod temp_bans;

pub(in crate::data_plane::xdp) use temp_bans::dispatcher_temp_bans;

pub(in crate::data_plane::xdp) fn dispatcher_status(args: XdpStatusArgs) -> Result<()> {
    let interface = resolve_interface_name(args.interface.as_deref())?;
    if let Some(summary) = existing_xdp_summary(&interface)? {
        println!("interface={interface} xdp_attached=true summary={summary}");
    } else {
        println!("interface={interface} xdp_attached=false");
    }
    let output = loader::run_xdp_loader_command(
        &args.xdp_loader_path,
        loader::xdp_loader_verbose_args(args.verbose, ["status"]),
    )
    .with_context(|| format!("failed to run xdp-loader status for interface '{interface}'"))?;
    loader::print_command_output(&output);
    loader::ensure_success("xdp-loader status", &output)
}

pub(in crate::data_plane::xdp) fn dispatcher_unload(args: XdpUnloadArgs) -> Result<()> {
    let interface = loader::require_explicit_interface(
        args.interface.as_deref(),
        "xdp unload requires --interface because it can detach dispatcher programs and remove bpffs pins",
    )?;
    loader::dispatcher_unload_inner(
        &interface,
        &args.xdp_loader_path,
        args.id,
        args.all,
        args.remove_pins,
        args.clean,
        args.verbose,
        false,
    )
}

pub(in crate::data_plane::xdp) fn dispatcher_replace(args: XdpReplaceArgs) -> Result<()> {
    let interface = loader::require_explicit_interface(
        args.interface.as_deref(),
        "xdp replace requires --interface because it unloads dispatcher programs before loading the replacement",
    )?;
    if args.id.is_some() || args.all || args.remove_pins || args.clean {
        loader::dispatcher_unload_inner(
            &interface,
            &args.xdp_loader_path,
            args.id,
            args.all,
            args.remove_pins,
            args.clean,
            args.verbose,
            true,
        )?;
    }
    let map_sizes = args.map_capacities.xdp_map_sizes();
    let _manager = LinuxXdpManager::attach(
        &interface,
        &args.xdp_object,
        &args.program,
        map_sizes,
        XdpAttachOptions {
            mode: args.xdp_mode,
            strategy: XdpAttachStrategy::Dispatcher,
            allow_replace: false,
            auto_resize_maps: true,
            run_priority: args.xdp_run_priority,
            loader_path: args.xdp_loader_path,
            bpftool_path: args.bpftool_path,
        },
    )?;
    println!(
        "dispatcher replacement loaded interface={} object={} program={} priority={} pins={}",
        interface,
        args.xdp_object,
        args.program,
        args.xdp_run_priority,
        map_pin_dir(&interface)?.display()
    );
    Ok(())
}

pub(in crate::data_plane::xdp) fn existing_xdp_summary(interface: &str) -> Result<Option<String>> {
    let output = std::process::Command::new("ip")
        .args(["-details", "link", "show", "dev", interface])
        .output()
        .with_context(|| format!("failed to inspect interface '{interface}' with ip"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "failed to inspect interface '{interface}': {}",
            stderr.trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let text = stdout.trim();
    let has_xdp = text.contains(" xdp ")
        || text.contains(" xdpgeneric ")
        || text.contains(" xdpdrv ")
        || text.contains(" xdpoffload ")
        || text.contains("prog/xdp");
    if !has_xdp {
        return Ok(None);
    }
    let summary = text
        .lines()
        .map(str::trim)
        .find(|line| {
            line.contains("xdp")
                || line.contains("prog/xdp")
                || line.contains("id ")
                || line.contains("tag ")
        })
        .unwrap_or("xdp program present")
        .to_string();
    Ok(Some(summary))
}
