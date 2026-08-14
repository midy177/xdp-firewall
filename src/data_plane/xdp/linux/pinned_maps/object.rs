use super::*;
use aya::{Ebpf, EbpfLoader};

pub(in crate::data_plane::xdp::linux) fn load_object_with_pinned_maps(
    object_path: &str,
    map_sizes: XdpMapSizes,
    pin_dir: &Path,
) -> Result<Ebpf> {
    let drop_event_entries = possible_cpu_map_entries()
        .context("failed to detect possible CPUs for drop_events map sizing")?;
    let mut loader = EbpfLoader::new();
    loader
        .default_map_pin_directory(pin_dir)
        .map_max_entries("rule_cidrs", map_sizes.rule_entries)
        .map_max_entries("geo_cidrs", map_sizes.geo_entries)
        .map_max_entries("trusted_cidrs", map_sizes.trusted_entries)
        .map_max_entries("country_rules", map_sizes.country_entries)
        .map_max_entries("rate_buckets", map_sizes.rate_entries)
        .map_max_entries("custom_rate_limits", map_sizes.custom_rate_limit_entries)
        .map_max_entries("temp_bans", map_sizes.temp_ban_entries)
        .map_max_entries("drop_events", drop_event_entries);
    loader
        .load_file(object_path)
        .with_context(|| format!("failed to load XDP object '{object_path}'"))
}

pub(in crate::data_plane::xdp::linux) fn take_maps(ebpf: &mut Ebpf) -> Result<XdpMapBundle> {
    Ok(XdpMapBundle {
        rule_cidrs: ebpf
            .take_map("rule_cidrs")
            .context("missing XDP map 'rule_cidrs'")?
            .try_into()
            .context("XDP map 'rule_cidrs' has unexpected type")?,
        geo_cidrs: ebpf
            .take_map("geo_cidrs")
            .context("missing XDP map 'geo_cidrs'")?
            .try_into()
            .context("XDP map 'geo_cidrs' has unexpected type")?,
        trusted_cidrs: ebpf
            .take_map("trusted_cidrs")
            .context("missing XDP map 'trusted_cidrs'")?
            .try_into()
            .context("XDP map 'trusted_cidrs' has unexpected type")?,
        country_rules: ebpf
            .take_map("country_rules")
            .context("missing XDP map 'country_rules'")?
            .try_into()
            .context("XDP map 'country_rules' has unexpected type")?,
        defense_policy: ebpf
            .take_map("defense_policy")
            .context("missing XDP map 'defense_policy'")?
            .try_into()
            .context("XDP map 'defense_policy' has unexpected type")?,
        custom_rate_limits: ebpf
            .take_map("custom_rate_limits")
            .context("missing XDP map 'custom_rate_limits'")?
            .try_into()
            .context("XDP map 'custom_rate_limits' has unexpected type")?,
        temp_bans: ebpf
            .take_map("temp_bans")
            .context("missing XDP map 'temp_bans'")?
            .try_into()
            .context("XDP map 'temp_bans' has unexpected type")?,
        drop_config: ebpf
            .take_map("drop_config")
            .context("missing XDP map 'drop_config'")?
            .try_into()
            .context("XDP map 'drop_config' has unexpected type")?,
        stats: ebpf
            .take_map("stats")
            .context("missing XDP map 'stats'")?
            .try_into()
            .context("XDP map 'stats' has unexpected type")?,
        drop_events: ebpf
            .take_map("drop_events")
            .context("missing XDP map 'drop_events'")?
            .try_into()
            .context("XDP map 'drop_events' has unexpected type")?,
    })
}

fn possible_cpu_map_entries() -> Result<u32> {
    let possible = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .context("failed to read /sys/devices/system/cpu/possible")?;
    let max_cpu = possible
        .trim()
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(parse_cpu_range_end)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("possible CPU set is empty")?;
    u32::try_from(max_cpu + 1).context("possible CPU id is outside u32 range")
}

fn parse_cpu_range_end(value: &str) -> Result<usize> {
    let value = value.trim();
    value
        .rsplit_once('-')
        .map_or(value, |(_, end)| end)
        .parse::<usize>()
        .with_context(|| format!("invalid CPU range '{value}'"))
}
