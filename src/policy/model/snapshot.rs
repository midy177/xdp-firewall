use super::{DEFAULT_POLICY_NAME, L4Protocol, RuleAction};
use crate::intelligence::threat;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub priority: i32,
    pub action: RuleAction,
    pub cidr: IpNet,
    pub protocol: L4Protocol,
    pub port: Option<u16>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoCountryPolicy {
    pub country: String,
    pub action: RuleAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpPrefixPolicy {
    pub cidr: IpNet,
    pub country: String,
}

pub const DEFAULT_IP_RATE_LIMIT_PPS: u32 = 5_000;
pub const DEFAULT_IP_RATE_LIMIT_BURST: u32 = 10_000;
pub const DEFAULT_FLOOD_PPS: u32 = 20_000;
pub const DEFAULT_FLOOD_BURST: u32 = 40_000;
pub const DEFAULT_FLOOD_BLOCK_SECONDS: u32 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicDefensePolicy {
    pub enabled: bool,
    pub ip_rate_limit_enabled: bool,
    pub ip_packets_per_second: Option<u32>,
    pub ip_burst: Option<u32>,
    pub flood_enabled: bool,
    pub flood_packets_per_second: Option<u32>,
    pub flood_burst: Option<u32>,
    pub flood_block_seconds: Option<u32>,
}

impl Default for DynamicDefensePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            ip_rate_limit_enabled: true,
            ip_packets_per_second: Some(DEFAULT_IP_RATE_LIMIT_PPS),
            ip_burst: Some(DEFAULT_IP_RATE_LIMIT_BURST),
            flood_enabled: true,
            flood_packets_per_second: Some(DEFAULT_FLOOD_PPS),
            flood_burst: Some(DEFAULT_FLOOD_BURST),
            flood_block_seconds: Some(DEFAULT_FLOOD_BLOCK_SECONDS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicRateLimitPolicy {
    pub priority: i32,
    pub protocol: L4Protocol,
    pub port: Option<u16>,
    pub packets_per_second: u32,
    pub burst: u32,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempBanPolicy {
    pub cidr: IpNet,
    pub protocol: L4Protocol,
    pub port: Option<u16>,
    pub expires_at: chrono::NaiveDateTime,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCidrPolicy {
    pub cidr: IpNet,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    #[serde(default = "default_policy_name", skip_serializing)]
    pub policy_name: String,
    pub version: i64,
    pub rules: Vec<FirewallRule>,
    pub geo_countries: Vec<GeoCountryPolicy>,
    #[serde(default)]
    pub geo_prefixes: Vec<GeoIpPrefixPolicy>,
    #[serde(default)]
    pub temp_bans: Vec<TempBanPolicy>,
    pub dynamic_defense: DynamicDefensePolicy,
    pub dynamic_rate_limits: Vec<DynamicRateLimitPolicy>,
    pub trusted_cidrs: Vec<TrustedCidrPolicy>,
    pub threat_sources: Vec<threat::ThreatSource>,
    #[serde(default)]
    pub threat_prefixes: Vec<threat::ThreatPrefix>,
}

fn default_policy_name() -> String {
    DEFAULT_POLICY_NAME.to_string()
}
