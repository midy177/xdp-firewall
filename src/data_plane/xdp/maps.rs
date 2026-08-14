use super::XdpMapSizes;
use anyhow::{Context as _, Result, bail};

#[cfg(any(target_os = "linux", test))]
pub(super) fn validate_map_capacity(required: XdpMapSizes, configured: XdpMapSizes) -> Result<()> {
    ensure_capacity("rule_cidrs", required.rule_entries, configured.rule_entries)?;
    ensure_capacity(
        "trusted_cidrs",
        required.trusted_entries,
        configured.trusted_entries,
    )?;
    ensure_capacity("geo_cidrs", required.geo_entries, configured.geo_entries)?;
    ensure_capacity(
        "country_rules",
        required.country_entries,
        configured.country_entries,
    )?;
    ensure_capacity(
        "custom_rate_limits",
        required.custom_rate_limit_entries,
        configured.custom_rate_limit_entries,
    )?;
    ensure_capacity(
        "temp_bans",
        required.temp_ban_entries,
        configured.temp_ban_entries,
    )?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn resized_map_sizes(
    current: XdpMapSizes,
    required: XdpMapSizes,
) -> Result<Option<XdpMapSizes>> {
    let resized = XdpMapSizes {
        rule_entries: expanded_capacity("rule_cidrs", current.rule_entries, required.rule_entries)?,
        geo_entries: expanded_capacity("geo_cidrs", current.geo_entries, required.geo_entries)?,
        trusted_entries: expanded_capacity(
            "trusted_cidrs",
            current.trusted_entries,
            required.trusted_entries,
        )?,
        country_entries: expanded_capacity(
            "country_rules",
            current.country_entries,
            required.country_entries,
        )?,
        rate_entries: current.rate_entries,
        custom_rate_limit_entries: expanded_capacity(
            "custom_rate_limits",
            current.custom_rate_limit_entries,
            required.custom_rate_limit_entries,
        )?,
        temp_ban_entries: expanded_capacity(
            "temp_bans",
            current.temp_ban_entries,
            required.temp_ban_entries,
        )?,
    };
    Ok((resized != current).then_some(resized))
}

#[cfg(target_os = "linux")]
pub(super) fn usize_to_u32(map: &str, value: usize) -> Result<u32> {
    u32::try_from(value).with_context(|| format!("{map} entry count {value} exceeds u32 max"))
}

#[cfg(any(target_os = "linux", test))]
fn expanded_capacity(map: &str, current: u32, required: u32) -> Result<u32> {
    if required <= current {
        return Ok(current);
    }
    let doubled = u64::from(current)
        .checked_mul(2)
        .with_context(|| format!("{map} capacity overflowed while resizing"))?;
    let target = doubled.max(u64::from(required)).max(1);
    let rounded = target
        .checked_next_power_of_two()
        .with_context(|| format!("{map} capacity overflowed while rounding resize target"))?;
    u32::try_from(rounded)
        .with_context(|| format!("{map} resized capacity {rounded} exceeds u32 max"))
}

#[cfg(any(target_os = "linux", test))]
fn ensure_capacity(map: &str, needed: u32, configured: u32) -> Result<()> {
    if needed > configured {
        bail!("{map} needs {needed} entries but map capacity is {configured}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
