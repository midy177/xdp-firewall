use crate::db::entities::{
    dynamic_defense, dynamic_rate_limit, firewall_rule, geo_country_policy, policy_version,
    temp_ban, threat_source, trusted_cidr,
};
use crate::intelligence::threat;
use anyhow::Result;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

use super::parse::{
    parse_dynamic_defense, parse_dynamic_rate_limit, parse_geo_country_policy, parse_rule,
    parse_temp_ban, parse_trusted_cidr,
};
use crate::policy::{
    model::{
        DynamicDefensePolicy, DynamicRateLimitPolicy, FirewallRule, GeoCountryPolicy,
        TempBanPolicy, TrustedCidrPolicy,
    },
    validate,
};

pub(super) async fn load_policy_version(db: &DatabaseConnection, policy_name: &str) -> Result<i64> {
    Ok(policy_version::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

pub(super) async fn load_firewall_rules(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<Vec<FirewallRule>> {
    firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(policy_name))
        .filter(firewall_rule::Column::Enabled.eq(true))
        .order_by_asc(firewall_rule::Column::Priority)
        .all(db)
        .await?
        .into_iter()
        .map(parse_rule)
        .collect()
}

pub(super) async fn load_geo_countries(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<Vec<GeoCountryPolicy>> {
    geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(policy_name))
        .filter(geo_country_policy::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(|row| parse_geo_country_policy(&row))
        .collect()
}

pub(super) async fn load_threat_sources(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<Vec<threat::ThreatSource>> {
    threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(threat::ThreatSource::try_from)
        .collect()
}

pub(super) async fn load_dynamic_defense(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<DynamicDefensePolicy> {
    let policy = dynamic_defense::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .as_ref()
        .map(parse_dynamic_defense)
        .transpose()?
        .unwrap_or_default();
    validate::validate_dynamic_defense_policy(&policy)?;
    Ok(policy)
}

pub(super) async fn load_dynamic_rate_limits(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<Vec<DynamicRateLimitPolicy>> {
    dynamic_rate_limit::Entity::find()
        .filter(dynamic_rate_limit::Column::PolicyName.eq(policy_name))
        .filter(dynamic_rate_limit::Column::Enabled.eq(true))
        .order_by_asc(dynamic_rate_limit::Column::Priority)
        .all(db)
        .await?
        .into_iter()
        .map(parse_dynamic_rate_limit)
        .collect()
}

pub(super) async fn load_active_temp_bans(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<Vec<TempBanPolicy>> {
    temp_ban::Entity::find()
        .filter(temp_ban::Column::PolicyName.eq(policy_name))
        .filter(temp_ban::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
        .order_by_asc(temp_ban::Column::ExpiresAt)
        .all(db)
        .await?
        .into_iter()
        .map(parse_temp_ban)
        .collect()
}

pub(super) async fn load_trusted_cidrs(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<Vec<TrustedCidrPolicy>> {
    trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(policy_name))
        .filter(trusted_cidr::Column::Enabled.eq(true))
        .order_by_asc(trusted_cidr::Column::Cidr)
        .all(db)
        .await?
        .into_iter()
        .map(parse_trusted_cidr)
        .collect()
}
