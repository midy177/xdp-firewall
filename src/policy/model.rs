use serde::{Deserialize, Serialize};

mod snapshot;
mod xdp;

pub use snapshot::{
    DEFAULT_FLOOD_BLOCK_SECONDS, DEFAULT_FLOOD_BURST, DEFAULT_FLOOD_PPS,
    DEFAULT_IP_RATE_LIMIT_BURST, DEFAULT_IP_RATE_LIMIT_PPS, DynamicDefensePolicy,
    DynamicRateLimitPolicy, FirewallRule, GeoCountryPolicy, GeoIpPrefixPolicy, PolicySnapshot,
    TempBanPolicy, TrustedCidrPolicy,
};
pub use xdp::{
    CompiledPolicy, XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix,
    XdpPrefixRule, XdpRuleSource, XdpTempBan, XdpTrustedPrefix,
};

pub const DEFAULT_POLICY_NAME: &str = "edge";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}
