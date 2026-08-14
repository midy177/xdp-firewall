use crate::db::{entities::dynamic_defense, scalars};
use crate::policy::model::DynamicDefensePolicy;
use anyhow::Result;
use sea_orm::Set;

pub(in crate::control_plane::api) fn dynamic_defense_active_model(
    policy_name: &str,
    data: &DynamicDefensePolicy,
    now: chrono::NaiveDateTime,
) -> Result<dynamic_defense::ActiveModel> {
    let mut active = dynamic_defense::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        updated_at: Set(now),
        ..Default::default()
    };
    set_dynamic_defense_fields(&mut active, data)?;
    Ok(active)
}

pub(in crate::control_plane::api) fn set_dynamic_defense_fields(
    active: &mut dynamic_defense::ActiveModel,
    data: &DynamicDefensePolicy,
) -> Result<()> {
    active.enabled = Set(data.enabled);
    active.ip_rate_limit_enabled = Set(data.ip_rate_limit_enabled);
    active.ip_packets_per_second = Set(scalars::optional_u32_to_i32(
        "ip_packets_per_second",
        data.ip_packets_per_second,
    )?);
    active.ip_burst = Set(scalars::optional_u32_to_i32("ip_burst", data.ip_burst)?);
    active.flood_enabled = Set(data.flood_enabled);
    active.flood_packets_per_second = Set(scalars::optional_u32_to_i32(
        "flood_packets_per_second",
        data.flood_packets_per_second,
    )?);
    active.flood_burst = Set(scalars::optional_u32_to_i32(
        "flood_burst",
        data.flood_burst,
    )?);
    active.flood_block_seconds = Set(scalars::optional_u32_to_i32(
        "flood_block_seconds",
        data.flood_block_seconds,
    )?);
    Ok(())
}

pub(in crate::control_plane::api) fn dynamic_defense_policy_from_model(
    row: &dynamic_defense::Model,
) -> Result<DynamicDefensePolicy> {
    Ok(DynamicDefensePolicy {
        enabled: row.enabled,
        ip_rate_limit_enabled: row.ip_rate_limit_enabled,
        ip_packets_per_second: scalars::optional_i32_to_u32(
            "ip_packets_per_second",
            row.ip_packets_per_second,
        )?,
        ip_burst: scalars::optional_i32_to_u32("ip_burst", row.ip_burst)?,
        flood_enabled: row.flood_enabled,
        flood_packets_per_second: scalars::optional_i32_to_u32(
            "flood_packets_per_second",
            row.flood_packets_per_second,
        )?,
        flood_burst: scalars::optional_i32_to_u32("flood_burst", row.flood_burst)?,
        flood_block_seconds: scalars::optional_i32_to_u32(
            "flood_block_seconds",
            row.flood_block_seconds,
        )?,
    })
}
