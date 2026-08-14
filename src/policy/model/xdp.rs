use super::{L4Protocol, RuleAction};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub version: i64,
    pub trusted_prefixes: Vec<XdpTrustedPrefix>,
    pub rules: Vec<XdpPrefixRule>,
    pub country_rules: Vec<XdpCountryRule>,
    pub temp_bans: Vec<XdpTempBan>,
    pub dynamic_defense: XdpDynamicDefense,
    pub dynamic_rate_limits: Vec<XdpDynamicRateLimit>,
    pub geo_prefixes: Vec<XdpGeoPrefix>,
    pub threat_prefixes: Vec<XdpPrefixRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpTrustedPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpPrefixRule {
    pub addr: IpAddr,
    pub prefix: u8,
    pub priority: i32,
    pub action: RuleAction,
    pub protocol: L4Protocol,
    pub port: u16,
    pub source: XdpRuleSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpRuleSource {
    FirewallRule,
    ThreatIntel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpGeoPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
    pub country: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpCountryRule {
    pub country: u16,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpTempBan {
    pub addr: IpAddr,
    pub prefix: u8,
    pub protocol: L4Protocol,
    pub port: u16,
    pub expires_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XdpDynamicDefense {
    pub enabled: bool,
    pub ip_rate_limit_enabled: bool,
    pub ip_packets_per_second: u32,
    pub ip_burst: u32,
    pub flood_enabled: bool,
    pub flood_packets_per_second: u32,
    pub flood_burst: u32,
    pub flood_block_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpDynamicRateLimit {
    pub protocol: L4Protocol,
    pub port: u16,
    pub packets_per_second: u32,
    pub burst: u32,
}
