use crate::policy::model::DynamicDefensePolicy;
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct UpdateDynamicDefenseRequest {
    pub(super) enabled: Option<bool>,
    pub(super) ip_rate_limit_enabled: Option<bool>,
    pub(super) ip_packets_per_second: Option<i32>,
    pub(super) ip_burst: Option<i32>,
    pub(super) flood_enabled: Option<bool>,
    pub(super) flood_packets_per_second: Option<i32>,
    pub(super) flood_burst: Option<i32>,
    pub(super) flood_block_seconds: Option<i32>,
}

pub(in crate::control_plane::api) fn dynamic_defense_policy_from_request(
    request: &UpdateDynamicDefenseRequest,
) -> Result<DynamicDefensePolicy> {
    let defaults = DynamicDefensePolicy::default();
    Ok(DynamicDefensePolicy {
        enabled: request.enabled.unwrap_or(defaults.enabled),
        ip_rate_limit_enabled: request
            .ip_rate_limit_enabled
            .unwrap_or(defaults.ip_rate_limit_enabled),
        ip_packets_per_second: optional_i32_to_u32(
            "ip_packets_per_second",
            request.ip_packets_per_second,
        )?
        .or(defaults.ip_packets_per_second),
        ip_burst: optional_i32_to_u32("ip_burst", request.ip_burst)?.or(defaults.ip_burst),
        flood_enabled: request.flood_enabled.unwrap_or(defaults.flood_enabled),
        flood_packets_per_second: optional_i32_to_u32(
            "flood_packets_per_second",
            request.flood_packets_per_second,
        )?
        .or(defaults.flood_packets_per_second),
        flood_burst: optional_i32_to_u32("flood_burst", request.flood_burst)?
            .or(defaults.flood_burst),
        flood_block_seconds: optional_i32_to_u32(
            "flood_block_seconds",
            request.flood_block_seconds,
        )?
        .or(defaults.flood_block_seconds),
    })
}

fn optional_i32_to_u32(label: &str, value: Option<i32>) -> Result<Option<u32>> {
    value
        .map(|value| u32::try_from(value).with_context(|| format!("{label} must not be negative")))
        .transpose()
}
