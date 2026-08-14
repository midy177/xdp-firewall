use super::model::{
    CompiledPolicy, DynamicDefensePolicy, DynamicRateLimitPolicy, FirewallRule, GeoCountryPolicy,
    GeoIpPrefixPolicy, L4Protocol, PolicySnapshot, RuleAction, TempBanPolicy, TrustedCidrPolicy,
    XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix, XdpPrefixRule,
    XdpRuleSource, XdpTempBan, XdpTrustedPrefix,
};
use crate::intelligence::{geo, threat::ThreatPrefix};
use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;

pub fn compile_policy(snapshot: &PolicySnapshot) -> Result<CompiledPolicy> {
    validate_policy(snapshot)?;

    Ok(CompiledPolicy {
        version: snapshot.version,
        trusted_prefixes: compile_trusted_prefixes(&snapshot.trusted_cidrs),
        rules: compile_firewall_rules(&snapshot.rules),
        country_rules: compile_country_rules(&snapshot.geo_countries)?,
        temp_bans: compile_active_temp_bans(&snapshot.temp_bans),
        dynamic_defense: compile_dynamic_defense(&snapshot.dynamic_defense),
        dynamic_rate_limits: compile_dynamic_rate_limits(&snapshot.dynamic_rate_limits),
        geo_prefixes: compile_geo_prefixes(&snapshot.geo_prefixes)?,
        threat_prefixes: compile_threat_prefixes(&snapshot.threat_prefixes),
    })
}

fn validate_policy(snapshot: &PolicySnapshot) -> Result<()> {
    super::validate::validate_dynamic_defense_policy(&snapshot.dynamic_defense)?;
    for limit in &snapshot.dynamic_rate_limits {
        super::validate::validate_dynamic_rate_limit_policy(limit)?;
    }
    Ok(())
}

fn compile_geo_prefixes(prefixes: &[GeoIpPrefixPolicy]) -> Result<Vec<XdpGeoPrefix>> {
    prefixes
        .iter()
        .map(|prefix| {
            let (addr, len) = cidr_network(prefix.cidr);
            Ok(XdpGeoPrefix {
                addr,
                prefix: len,
                country: geo::encode_country(&prefix.country)?,
            })
        })
        .collect()
}

fn compile_threat_prefixes(prefixes: &[ThreatPrefix]) -> Vec<XdpPrefixRule> {
    prefixes
        .iter()
        .map(|prefix| XdpPrefixRule {
            addr: prefix.addr,
            prefix: prefix.prefix,
            priority: i32::MIN,
            action: RuleAction::Deny,
            protocol: L4Protocol::Any,
            port: 0,
            source: XdpRuleSource::ThreatIntel,
        })
        .collect()
}

fn compile_trusted_prefixes(prefixes: &[TrustedCidrPolicy]) -> Vec<XdpTrustedPrefix> {
    prefixes
        .iter()
        .map(|trusted| {
            let (addr, prefix) = cidr_network(trusted.cidr);
            XdpTrustedPrefix { addr, prefix }
        })
        .collect()
}

fn compile_firewall_rules(rules: &[FirewallRule]) -> Vec<XdpPrefixRule> {
    rules
        .iter()
        .map(|rule| {
            let (addr, prefix) = cidr_network(rule.cidr);
            XdpPrefixRule {
                addr,
                prefix,
                priority: rule.priority,
                action: rule.action,
                protocol: rule.protocol,
                port: rule.port.unwrap_or(0),
                source: XdpRuleSource::FirewallRule,
            }
        })
        .collect()
}

fn compile_country_rules(policies: &[GeoCountryPolicy]) -> Result<Vec<XdpCountryRule>> {
    policies
        .iter()
        .map(|policy| {
            Ok(XdpCountryRule {
                country: geo::encode_country(&policy.country)?,
                action: policy.action,
            })
        })
        .collect()
}

fn compile_active_temp_bans(bans: &[TempBanPolicy]) -> Vec<XdpTempBan> {
    bans.iter()
        .filter(|ban| ban.expires_at > chrono::Utc::now().naive_utc())
        .map(|ban| {
            let (addr, prefix) = cidr_network(ban.cidr);
            XdpTempBan {
                addr,
                prefix,
                protocol: ban.protocol,
                port: ban.port.unwrap_or(0),
                expires_at: ban.expires_at,
            }
        })
        .collect()
}

fn compile_dynamic_defense(policy: &DynamicDefensePolicy) -> XdpDynamicDefense {
    XdpDynamicDefense {
        enabled: policy.enabled,
        ip_rate_limit_enabled: policy.ip_rate_limit_enabled,
        ip_packets_per_second: policy.ip_packets_per_second.unwrap_or(0),
        ip_burst: policy.ip_burst.unwrap_or(0),
        flood_enabled: policy.flood_enabled,
        flood_packets_per_second: policy.flood_packets_per_second.unwrap_or(0),
        flood_burst: policy.flood_burst.unwrap_or(0),
        flood_block_seconds: policy.flood_block_seconds.unwrap_or(0),
    }
}

fn compile_dynamic_rate_limits(limits: &[DynamicRateLimitPolicy]) -> Vec<XdpDynamicRateLimit> {
    limits
        .iter()
        .map(|limit| XdpDynamicRateLimit {
            protocol: limit.protocol,
            port: limit.port.unwrap_or(0),
            packets_per_second: limit.packets_per_second,
            burst: limit.burst,
        })
        .collect()
}

fn cidr_network(cidr: IpNet) -> (IpAddr, u8) {
    match cidr {
        IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
        IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
    }
}
