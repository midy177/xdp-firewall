use super::*;
use crate::policy::model::{
    DEFAULT_FLOOD_BLOCK_SECONDS, DEFAULT_FLOOD_PPS, DEFAULT_IP_RATE_LIMIT_BURST,
};

#[test]
fn rejects_enabled_dynamic_defense_with_zero_values() {
    let policy = DynamicDefensePolicy {
        enabled: true,
        ip_rate_limit_enabled: true,
        ip_packets_per_second: Some(0),
        ip_burst: Some(DEFAULT_IP_RATE_LIMIT_BURST),
        flood_enabled: false,
        flood_packets_per_second: None,
        flood_burst: None,
        flood_block_seconds: None,
    };

    assert!(validate_dynamic_defense_policy(&policy).is_err());
}

#[test]
fn rejects_enabled_dynamic_defense_with_missing_values() {
    let policy = DynamicDefensePolicy {
        enabled: true,
        ip_rate_limit_enabled: false,
        ip_packets_per_second: None,
        ip_burst: None,
        flood_enabled: true,
        flood_packets_per_second: Some(DEFAULT_FLOOD_PPS),
        flood_burst: None,
        flood_block_seconds: Some(DEFAULT_FLOOD_BLOCK_SECONDS),
    };

    assert!(validate_dynamic_defense_policy(&policy).is_err());
}

#[test]
fn accepts_custom_dynamic_rate_limit_by_port_only() {
    let policy = DynamicRateLimitPolicy {
        priority: 10,
        protocol: L4Protocol::Any,
        port: Some(443),
        packets_per_second: 1_000,
        burst: 2_000,
        comment: None,
    };

    assert!(validate_dynamic_rate_limit_policy(&policy).is_ok());
}

#[test]
fn rejects_custom_dynamic_rate_limit_icmp_port() {
    let policy = DynamicRateLimitPolicy {
        priority: 10,
        protocol: L4Protocol::Icmp,
        port: Some(443),
        packets_per_second: 1_000,
        burst: 2_000,
        comment: None,
    };

    assert!(validate_dynamic_rate_limit_policy(&policy).is_err());
}
