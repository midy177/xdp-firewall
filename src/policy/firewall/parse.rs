use crate::db::{
    entities::{
        dynamic_defense, dynamic_rate_limit, firewall_rule, geo_country_policy, temp_ban,
        trusted_cidr,
    },
    scalars,
};
use crate::intelligence::geo;
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::net::IpAddr;

use super::super::{
    model::{
        DynamicDefensePolicy, DynamicRateLimitPolicy, FirewallRule, GeoCountryPolicy,
        GeoIpPrefixPolicy, L4Protocol, TempBanPolicy, TrustedCidrPolicy,
    },
    validate,
};

mod common;

use common::{parse_action, parse_optional_port, parse_protocol};

pub(super) fn parse_rule(row: firewall_rule::Model) -> Result<FirewallRule> {
    Ok(FirewallRule {
        priority: row.priority,
        action: parse_action(&row.action)?,
        cidr: row
            .cidr
            .parse()
            .with_context(|| format!("invalid CIDR '{}'", row.cidr))?,
        protocol: row
            .protocol
            .as_deref()
            .map(parse_protocol)
            .transpose()?
            .unwrap_or(L4Protocol::Any),
        port: parse_optional_port(row.port, "firewall rule port")?,
        comment: row.comment,
    })
}

pub(super) fn parse_geo_country_policy(
    row: &geo_country_policy::Model,
) -> Result<GeoCountryPolicy> {
    Ok(GeoCountryPolicy {
        country: geo::normalize_country(&row.country)?,
        action: parse_action(&row.action)?,
    })
}

pub(super) fn parse_geo_prefix(prefix: geo::GeoPrefix) -> Result<GeoIpPrefixPolicy> {
    Ok(GeoIpPrefixPolicy {
        cidr: geo_prefix_to_ipnet(prefix.addr, prefix.prefix)?,
        country: geo::decode_country(prefix.country)
            .with_context(|| "invalid persisted geo country code")?,
    })
}

fn geo_prefix_to_ipnet(addr: IpAddr, prefix: u8) -> Result<IpNet> {
    IpNet::new(addr, prefix).with_context(|| format!("invalid geo prefix {addr}/{prefix}"))
}

pub(super) fn parse_dynamic_defense(row: &dynamic_defense::Model) -> Result<DynamicDefensePolicy> {
    Ok(DynamicDefensePolicy {
        enabled: row.enabled,
        ip_rate_limit_enabled: row.ip_rate_limit_enabled,
        ip_packets_per_second: scalars::optional_i32_to_u32(
            "dynamic defense ip_packets_per_second",
            row.ip_packets_per_second,
        )?,
        ip_burst: scalars::optional_i32_to_u32("dynamic defense ip_burst", row.ip_burst)?,
        flood_enabled: row.flood_enabled,
        flood_packets_per_second: scalars::optional_i32_to_u32(
            "dynamic defense flood_packets_per_second",
            row.flood_packets_per_second,
        )?,
        flood_burst: scalars::optional_i32_to_u32("dynamic defense flood_burst", row.flood_burst)?,
        flood_block_seconds: scalars::optional_i32_to_u32(
            "dynamic defense flood_block_seconds",
            row.flood_block_seconds,
        )?,
    })
}

pub(super) fn parse_dynamic_rate_limit(
    row: dynamic_rate_limit::Model,
) -> Result<DynamicRateLimitPolicy> {
    let policy = DynamicRateLimitPolicy {
        priority: row.priority,
        protocol: parse_protocol(&row.protocol)?,
        port: parse_optional_port(row.port, "dynamic rate limit port")?,
        packets_per_second: scalars::i32_to_u32(
            "dynamic rate limit packets_per_second",
            row.packets_per_second,
        )?,
        burst: scalars::i32_to_u32("dynamic rate limit burst", row.burst)?,
        comment: row.comment,
    };
    validate::validate_dynamic_rate_limit_policy(&policy)?;
    Ok(policy)
}

pub(super) fn parse_temp_ban(row: temp_ban::Model) -> Result<TempBanPolicy> {
    let policy = TempBanPolicy {
        cidr: row
            .cidr
            .parse()
            .with_context(|| format!("invalid temporary ban CIDR '{}'", row.cidr))?,
        protocol: parse_protocol(&row.protocol)?,
        port: parse_optional_port(row.port, "temporary ban port")?,
        expires_at: row.expires_at,
        comment: row.comment,
    };
    validate::validate_temp_ban_policy(&policy)?;
    Ok(policy)
}

pub(super) fn parse_trusted_cidr(row: trusted_cidr::Model) -> Result<TrustedCidrPolicy> {
    Ok(TrustedCidrPolicy {
        cidr: row
            .cidr
            .parse()
            .with_context(|| format!("invalid trusted CIDR '{}'", row.cidr))?,
        comment: row.comment,
    })
}
