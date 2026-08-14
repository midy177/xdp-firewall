use super::*;
use anyhow::{Context, Result, bail};
use aya::maps::{
    Array as AyaArray, HashMap as AyaHashMap, IterableMap, LpmTrie, Map, MapData, MapType,
    PerCpuArray, PerfEventArray,
};
use std::path::Path;
use tracing::warn;

mod object;
mod temp_bans;

pub(super) use object::{load_object_with_pinned_maps, take_maps};
pub(super) use temp_bans::pinned_temp_bans;

pub(super) struct XdpMapBundle {
    pub(super) rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
    pub(super) geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
    pub(super) trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
    pub(super) country_rules: AyaHashMap<MapData, u32, CountryValue>,
    pub(super) defense_policy: AyaArray<MapData, DefenseValue>,
    pub(super) custom_rate_limits: AyaHashMap<MapData, CustomRateKey, CustomRateValue>,
    pub(super) temp_bans: LpmTrie<MapData, TempBanData, TempBanValue>,
    pub(super) drop_config: AyaArray<MapData, DropConfigValue>,
    pub(super) stats: PerCpuArray<MapData, u64>,
    pub(super) drop_events: PerfEventArray<MapData>,
}

pub(super) fn prepare_map_pin_dir(pin_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(pin_dir).with_context(|| {
        format!(
            "failed to create bpffs map pin directory '{}'",
            pin_dir.display()
        )
    })?;
    Ok(())
}

pub(super) fn actual_map_sizes(maps: &XdpMapBundle, requested: XdpMapSizes) -> Result<XdpMapSizes> {
    Ok(XdpMapSizes {
        rule_entries: map_max_entries("rule_cidrs", maps.rule_cidrs.map())?,
        geo_entries: map_max_entries("geo_cidrs", maps.geo_cidrs.map())?,
        trusted_entries: map_max_entries("trusted_cidrs", maps.trusted_cidrs.map())?,
        country_entries: map_max_entries("country_rules", maps.country_rules.map())?,
        rate_entries: requested.rate_entries,
        custom_rate_limit_entries: map_max_entries(
            "custom_rate_limits",
            maps.custom_rate_limits.map(),
        )?,
        temp_ban_entries: map_max_entries("temp_bans", maps.temp_bans.map())?,
    })
}

pub(super) fn recreate_incompatible_pinned_maps(
    interface: &str,
    program_name: &str,
    attach_options: &XdpAttachOptions,
    pin_dir: &Path,
) -> Result<()> {
    let Some(temp_bans_map_type) = pinned_map_type(pin_dir, "temp_bans")? else {
        return Ok(());
    };
    if temp_bans_map_type == MapType::LpmTrie {
        return Ok(());
    }

    match attach_options.strategy {
        XdpAttachStrategy::Direct if !attach_options.allow_replace => {
            loader::ensure_no_existing_xdp(interface)?;
        }
        XdpAttachStrategy::Direct => {}
        XdpAttachStrategy::Dispatcher => {
            loader::unload_dispatcher_programs_by_name(
                &attach_options.loader_path,
                interface,
                program_name,
                false,
            )?;
        }
    }

    warn!(
        interface,
        strategy = %attach_options.strategy.as_str(),
        pin_dir = %pin_dir.display(),
        old_temp_bans_map_type = ?temp_bans_map_type,
        "recreating pinned XDP maps because temp_bans map type changed"
    );
    std::fs::remove_dir_all(pin_dir).with_context(|| {
        format!(
            "failed to remove incompatible pinned map directory '{}'",
            pin_dir.display()
        )
    })?;
    std::fs::create_dir_all(pin_dir).with_context(|| {
        format!(
            "failed to recreate bpffs map pin directory '{}'",
            pin_dir.display()
        )
    })?;
    Ok(())
}

fn pinned_map_type(pin_dir: &Path, name: &str) -> Result<Option<MapType>> {
    let path = pin_dir.join(name);
    if !path.exists() {
        return Ok(None);
    }
    let map = MapData::from_pin(&path)
        .with_context(|| format!("failed to open pinned XDP map '{}'", path.display()))?;
    let info = map
        .info()
        .with_context(|| format!("failed to inspect pinned XDP map '{}'", path.display()))?;
    info.map_type()
        .with_context(|| format!("failed to read pinned XDP map type '{}'", path.display()))
        .map(Some)
}

fn map_max_entries(name: &str, map: &MapData) -> Result<u32> {
    let info = map
        .info()
        .with_context(|| format!("failed to inspect XDP map '{name}'"))?;
    Ok(info.max_entries())
}
