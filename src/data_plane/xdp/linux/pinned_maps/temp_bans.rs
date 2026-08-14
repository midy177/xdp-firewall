use super::*;

pub(in crate::data_plane::xdp::linux) fn pinned_temp_bans(
    interface: &str,
) -> Result<Vec<PinnedTempBanEntry>> {
    let path = map_pin_dir(interface)?.join("temp_bans");
    let map = MapData::from_pin(&path)
        .with_context(|| format!("failed to open pinned temp_bans map '{}'", path.display()))?;
    let map_type = map
        .info()
        .context("failed to inspect pinned temp_bans map")?
        .map_type()
        .context("failed to read pinned temp_bans map type")?;
    if map_type != MapType::LpmTrie {
        bail!(
            "pinned temp_bans map has type {:?}; CIDR temporary bans require lpm_trie. Restart a CIDR-capable agent or unload with --remove-pins to recreate pinned maps.",
            map_type
        );
    }
    let temp_bans: LpmTrie<MapData, TempBanData, TempBanValue> = Map::LpmTrie(map)
        .try_into()
        .context("pinned temp_bans map has unexpected type")?;
    let now = monotonic_now_ns()?;
    let mut entries = temp_bans
        .iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to list pinned temp_bans entries")?
        .into_iter()
        .map(|(key, value)| pinned_temp_ban_entry(key, value, now))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.cidr
            .cmp(&right.cidr)
            .then_with(|| left.protocol.cmp(&right.protocol))
            .then_with(|| left.port.cmp(&right.port))
    });
    Ok(entries)
}

fn pinned_temp_ban_entry(
    key: TempBanKey,
    value: TempBanValue,
    monotonic_now_ns: u64,
) -> PinnedTempBanEntry {
    let data = key.data();
    let prefix = key.prefix_len().saturating_sub(32);
    let addr = map_addr(data.family, data.addr);
    let remaining_ns = i128::from(value.expires_at_ns) - i128::from(monotonic_now_ns);
    PinnedTempBanEntry {
        cidr: format!("{addr}/{prefix}"),
        protocol: protocol_name(data.proto).to_string(),
        port: match u16::from_be(data.dport) {
            0 => "*".to_string(),
            port => port.to_string(),
        },
        expires_at_ns: value.expires_at_ns,
        remaining_seconds: (remaining_ns / 1_000_000_000) as i64,
        active: value.expires_at_ns > monotonic_now_ns,
    }
}
