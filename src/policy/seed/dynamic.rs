use crate::{
    db::{entities::dynamic_defense, scalars::optional_u32_to_i32},
    policy::model::DynamicDefensePolicy,
};
use anyhow::Result;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Set};

pub(super) async fn insert_default_dynamic_defense(
    db: &impl ConnectionTrait,
    policy_name: &str,
) -> Result<()> {
    ensure_default_dynamic_defense_exists(db, policy_name, chrono::Utc::now().naive_utc()).await
}

pub(super) async fn ensure_default_dynamic_defense_exists(
    db: &impl ConnectionTrait,
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    if dynamic_defense::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .is_some()
    {
        return Ok(());
    }
    default_dynamic_defense_active_model(policy_name, now)?
        .insert(db)
        .await?;
    Ok(())
}

pub(super) fn default_dynamic_defense_active_model(
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> Result<dynamic_defense::ActiveModel> {
    let defaults = DynamicDefensePolicy::default();
    Ok(dynamic_defense::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        enabled: Set(defaults.enabled),
        ip_rate_limit_enabled: Set(defaults.ip_rate_limit_enabled),
        ip_packets_per_second: Set(optional_u32_to_i32(
            "ip_packets_per_second",
            defaults.ip_packets_per_second,
        )?),
        ip_burst: Set(optional_u32_to_i32("ip_burst", defaults.ip_burst)?),
        flood_enabled: Set(defaults.flood_enabled),
        flood_packets_per_second: Set(optional_u32_to_i32(
            "flood_packets_per_second",
            defaults.flood_packets_per_second,
        )?),
        flood_burst: Set(optional_u32_to_i32("flood_burst", defaults.flood_burst)?),
        flood_block_seconds: Set(optional_u32_to_i32(
            "flood_block_seconds",
            defaults.flood_block_seconds,
        )?),
        updated_at: Set(now),
    })
}
