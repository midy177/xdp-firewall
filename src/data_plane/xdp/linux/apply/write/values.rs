use crate::data_plane::xdp::{
    CountryValue, CustomRateValue, DefenseValue, GeoValue, Result, RuleValue, TempBanValue,
    XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix, XdpPrefixRule,
    XdpTempBan, action_code, rule_source_code,
};
use anyhow::Context;

pub(super) fn defense_value(policy: &XdpDynamicDefense) -> DefenseValue {
    DefenseValue {
        enabled: u8::from(policy.enabled),
        ip_rate_limit_enabled: u8::from(policy.ip_rate_limit_enabled),
        flood_enabled: u8::from(policy.flood_enabled),
        pad: 0,
        ip_packets_per_second: policy.ip_packets_per_second,
        ip_burst: policy.ip_burst,
        flood_packets_per_second: policy.flood_packets_per_second,
        flood_burst: policy.flood_burst,
        flood_block_ns: u64::from(policy.flood_block_seconds) * 1_000_000_000,
    }
}

pub(super) fn rule_value(rule: &XdpPrefixRule) -> RuleValue {
    RuleValue {
        action: action_code(rule.action),
        source: rule_source_code(rule.source),
        pad: [0; 2],
        priority: rule.priority,
    }
}

pub(super) fn custom_rate_value(limit: &XdpDynamicRateLimit) -> CustomRateValue {
    CustomRateValue {
        packets_per_second: limit.packets_per_second,
        burst: limit.burst,
    }
}

pub(super) fn temp_ban_value(
    ban: &XdpTempBan,
    wall_now: chrono::NaiveDateTime,
    monotonic_now_ns: u64,
) -> Result<Option<TempBanValue>> {
    let Some(remaining_ns) = ban
        .expires_at
        .signed_duration_since(wall_now)
        .num_nanoseconds()
    else {
        return Ok(None);
    };
    if remaining_ns <= 0 {
        return Ok(None);
    }
    let expires_at_ns = monotonic_now_ns
        .checked_add(remaining_ns as u64)
        .context("temporary ban monotonic expiration overflowed")?;
    Ok(Some(TempBanValue { expires_at_ns }))
}

pub(super) fn geo_value(prefix: &XdpGeoPrefix) -> GeoValue {
    GeoValue {
        country: prefix.country,
    }
}

pub(super) fn country_value(country: &XdpCountryRule) -> CountryValue {
    CountryValue {
        action: action_code(country.action),
    }
}
