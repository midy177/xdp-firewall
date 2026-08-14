use crate::intelligence::{geo, threat};
use anyhow::Result;
use sea_orm::DatabaseConnection;

use super::model::{GeoIpPrefixPolicy, PolicySnapshot};

mod loaders;
mod parse;

use loaders::{
    load_active_temp_bans, load_dynamic_defense, load_dynamic_rate_limits, load_firewall_rules,
    load_geo_countries, load_policy_version, load_threat_sources, load_trusted_cidrs,
};
use parse::parse_geo_prefix;

pub async fn load_policy(db: &DatabaseConnection, policy_name: &str) -> Result<PolicySnapshot> {
    load_policy_with_geo_prefixes(db, policy_name, true).await
}

pub async fn load_policy_without_geo_prefixes(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<PolicySnapshot> {
    load_policy_with_geo_prefixes(db, policy_name, false).await
}

async fn load_policy_with_geo_prefixes(
    db: &DatabaseConnection,
    policy_name: &str,
    include_geo_prefixes: bool,
) -> Result<PolicySnapshot> {
    let version = load_policy_version(db, policy_name).await?;
    let rules = load_firewall_rules(db, policy_name).await?;
    let geo_countries = load_geo_countries(db, policy_name).await?;
    let geo_country_codes = geo_countries
        .iter()
        .map(|policy| policy.country.clone())
        .collect::<Vec<_>>();
    let geo_prefixes = load_geo_prefixes(db, &geo_country_codes, include_geo_prefixes).await?;
    let threat_sources = load_threat_sources(db, policy_name).await?;
    let threat_source_names = threat_sources
        .iter()
        .map(|source| source.name.clone())
        .collect::<Vec<_>>();
    let threat_prefixes =
        threat::load_persisted_threat_prefixes(db, policy_name, &threat_source_names).await?;
    let dynamic_defense = load_dynamic_defense(db, policy_name).await?;
    let dynamic_rate_limits = load_dynamic_rate_limits(db, policy_name).await?;
    let temp_bans = load_active_temp_bans(db, policy_name).await?;
    let trusted_cidrs = load_trusted_cidrs(db, policy_name).await?;

    Ok(PolicySnapshot {
        policy_name: policy_name.to_string(),
        version,
        rules,
        geo_countries,
        geo_prefixes,
        temp_bans,
        dynamic_defense,
        dynamic_rate_limits,
        trusted_cidrs,
        threat_sources,
        threat_prefixes,
    })
}

async fn load_geo_prefixes(
    db: &DatabaseConnection,
    country_codes: &[String],
    include_geo_prefixes: bool,
) -> Result<Vec<GeoIpPrefixPolicy>> {
    if !include_geo_prefixes {
        return Ok(Vec::new());
    }
    geo::load_persisted_geo_prefixes(db, country_codes)
        .await?
        .into_iter()
        .map(parse_geo_prefix)
        .collect()
}

#[cfg(test)]
mod tests;
