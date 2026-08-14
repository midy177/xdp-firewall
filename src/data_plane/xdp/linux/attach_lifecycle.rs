use super::*;
use aya::programs::Xdp;

pub(super) struct AttachedManagerParts<'a> {
    pub(super) interface: &'a str,
    pub(super) object_path: &'a str,
    pub(super) program_name: &'a str,
    pub(super) attach_options: &'a XdpAttachOptions,
    pub(super) pin_dir: &'a Path,
    pub(super) direct_netlink_link: Option<DirectNetlinkLink>,
    pub(super) ebpf: Ebpf,
    pub(super) maps: XdpMapBundle,
    pub(super) map_sizes: XdpMapSizes,
    pub(super) local_interface_cidrs: Vec<LocalInterfaceCidr>,
}

pub(super) fn attach_loaded_program(
    ebpf: &mut Ebpf,
    interface: &str,
    object_path: &str,
    program_name: &str,
    attach_options: &XdpAttachOptions,
    pin_dir: &Path,
    dispatcher_loaded: &mut bool,
) -> Result<Option<DirectNetlinkLink>> {
    match attach_options.strategy {
        XdpAttachStrategy::Direct => {
            attach_direct_program(ebpf, interface, program_name, attach_options)
        }
        XdpAttachStrategy::Dispatcher => {
            attach_dispatcher_program(
                interface,
                object_path,
                program_name,
                attach_options,
                pin_dir,
            )?;
            *dispatcher_loaded = true;
            Ok(None)
        }
    }
}

fn attach_direct_program(
    ebpf: &mut Ebpf,
    interface: &str,
    program_name: &str,
    attach_options: &XdpAttachOptions,
) -> Result<Option<DirectNetlinkLink>> {
    if !attach_options.allow_replace {
        loader::ensure_no_existing_xdp(interface)?;
    }
    let program: &mut Xdp = ebpf
        .program_mut(program_name)
        .with_context(|| format!("XDP program '{program_name}' is missing"))?
        .try_into()
        .with_context(|| format!("program '{program_name}' is not XDP"))?;
    program.load().context("failed to load XDP program")?;
    netlink::attach_program(
        program,
        interface,
        attach_options.mode,
        attach_options.allow_replace,
        &attach_options.bpftool_path,
    )
}

fn attach_dispatcher_program(
    interface: &str,
    object_path: &str,
    program_name: &str,
    attach_options: &XdpAttachOptions,
    pin_dir: &Path,
) -> Result<()> {
    loader::unload_dispatcher_programs_by_name(
        &attach_options.loader_path,
        interface,
        program_name,
        false,
    )?;
    loader::run_xdp_loader_load(
        interface,
        object_path,
        program_name,
        attach_options,
        pin_dir,
    )?;
    loader::verify_dispatcher_map_identity(
        &attach_options.loader_path,
        &attach_options.bpftool_path,
        interface,
        program_name,
        pin_dir,
    )
}

pub(super) fn build_attached_manager(
    mut parts: AttachedManagerParts<'_>,
) -> Result<LinuxXdpManager> {
    set_drop_config(&mut parts.maps.drop_config, false)?;
    info!(
        interface = parts.interface,
        strategy = %parts.attach_options.strategy.as_str(),
        pin_dir = %parts.pin_dir.display(),
        local_interface_cidrs = %format_local_interface_cidrs(&parts.local_interface_cidrs),
        local_interface_cidr_count = parts.local_interface_cidrs.len(),
        "XDP maps ready"
    );

    Ok(LinuxXdpManager {
        interface: parts.interface.to_string(),
        object_path: parts.object_path.to_string(),
        program_name: parts.program_name.to_string(),
        attach_options: parts.attach_options.clone(),
        _direct_netlink_link: parts.direct_netlink_link,
        _ebpf: parts.ebpf,
        rule_cidrs: parts.maps.rule_cidrs,
        geo_cidrs: parts.maps.geo_cidrs,
        trusted_cidrs: parts.maps.trusted_cidrs,
        country_rules: parts.maps.country_rules,
        defense_policy: parts.maps.defense_policy,
        custom_rate_limits: parts.maps.custom_rate_limits,
        temp_bans: parts.maps.temp_bans,
        drop_config: parts.maps.drop_config,
        stats: parts.maps.stats,
        _drop_events: parts.maps.drop_events,
        map_sizes: parts.map_sizes,
        local_interface_cidrs: parts.local_interface_cidrs,
    })
}
