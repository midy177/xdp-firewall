use super::*;
use anyhow::{Context, bail};
use aya::{
    Ebpf,
    maps::{
        Array as AyaArray, HashMap as AyaHashMap, LpmTrie, MapData, PerCpuArray, PerfEventArray,
    },
};
use std::path::Path;
use tracing::{debug, info};

mod apply;
mod attach_lifecycle;
mod dispatcher;
mod drop_config;
mod loader;
mod netlink;
mod pending;
mod pinned_maps;
mod stats;
mod time;

use attach_lifecycle::{AttachedManagerParts, attach_loaded_program, build_attached_manager};
pub(in crate::data_plane::xdp) use dispatcher::{
    dispatcher_replace, dispatcher_status, dispatcher_temp_bans, dispatcher_unload,
    existing_xdp_summary,
};
pub(in crate::data_plane::xdp) use drop_config::set_drop_config;
use netlink::DirectNetlinkLink;
use pinned_maps::{
    XdpMapBundle, actual_map_sizes, load_object_with_pinned_maps, pinned_temp_bans,
    prepare_map_pin_dir, recreate_incompatible_pinned_maps, take_maps,
};
pub(in crate::data_plane::xdp) use time::monotonic_now_ns;

pub struct LinuxXdpManager {
    interface: String,
    object_path: String,
    program_name: String,
    attach_options: XdpAttachOptions,
    _direct_netlink_link: Option<DirectNetlinkLink>,
    _ebpf: Ebpf,
    rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
    geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
    trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
    country_rules: AyaHashMap<MapData, u32, CountryValue>,
    defense_policy: AyaArray<MapData, DefenseValue>,
    custom_rate_limits: AyaHashMap<MapData, CustomRateKey, CustomRateValue>,
    temp_bans: LpmTrie<MapData, TempBanData, TempBanValue>,
    drop_config: AyaArray<MapData, DropConfigValue>,
    stats: PerCpuArray<MapData, u64>,
    _drop_events: PerfEventArray<MapData>,
    map_sizes: XdpMapSizes,
    local_interface_cidrs: Vec<LocalInterfaceCidr>,
}

impl LinuxXdpManager {
    pub fn attach(
        interface: &str,
        object_path: &str,
        program_name: &str,
        map_sizes: XdpMapSizes,
        attach_options: XdpAttachOptions,
    ) -> Result<Self> {
        if !Path::new(object_path).exists() {
            bail!("XDP object '{}' does not exist", object_path);
        }
        let pin_dir = map_pin_dir(interface)?;
        let pin_dir_existed = pin_dir.exists();
        let mut dispatcher_loaded = false;
        let attach_result = (|| -> Result<Self> {
            prepare_map_pin_dir(&pin_dir)?;
            recreate_incompatible_pinned_maps(interface, program_name, &attach_options, &pin_dir)?;
            let mut ebpf = load_object_with_pinned_maps(object_path, map_sizes, &pin_dir)?;
            let direct_netlink_link = attach_loaded_program(
                &mut ebpf,
                interface,
                object_path,
                program_name,
                &attach_options,
                &pin_dir,
                &mut dispatcher_loaded,
            )?;
            let maps = take_maps(&mut ebpf)?;
            let actual_map_sizes = actual_map_sizes(&maps, map_sizes)?;
            let local_interface_cidrs = local_interface_cidrs(interface)?;
            build_attached_manager(AttachedManagerParts {
                interface,
                object_path,
                program_name,
                attach_options: &attach_options,
                pin_dir: &pin_dir,
                direct_netlink_link,
                ebpf,
                maps,
                map_sizes: actual_map_sizes,
                local_interface_cidrs,
            })
        })();
        if let Err(err) = attach_result {
            loader::rollback_failed_attach(
                interface,
                program_name,
                &attach_options,
                &pin_dir,
                pin_dir_existed,
                dispatcher_loaded,
            );
            return Err(err);
        }
        attach_result
    }

    pub fn interface_name(&self) -> &str {
        &self.interface
    }

    pub fn interface_ips(&self) -> Vec<IpAddr> {
        self.local_interface_cidrs
            .iter()
            .map(|cidr| cidr.ip)
            .collect()
    }
}
