use super::{
    CustomRateId, CustomRateKey, GeoData, GeoId, GeoKey, RuleData, RuleId, RuleKey, TempBanData,
    TempBanId, TempBanKey, TrustedData, TrustedId, TrustedKey, addr_bytes, map_addr, proto_code,
};
use crate::policy::model::{L4Protocol, XdpRuleSource};
use aya::maps::lpm_trie::Key as LpmKey;
use std::net::IpAddr;

pub(in crate::data_plane::xdp) fn rule_source_order(source: XdpRuleSource) -> u8 {
    match source {
        XdpRuleSource::ThreatIntel => 0,
        XdpRuleSource::FirewallRule => 1,
    }
}

pub(in crate::data_plane::xdp) fn country_key(country: u16) -> u32 {
    u32::from(country)
}

pub(in crate::data_plane::xdp) fn rule_key(
    addr: IpAddr,
    prefix: u8,
    protocol: L4Protocol,
    port: u16,
) -> RuleKey {
    let family = if addr.is_ipv4() { 4 } else { 6 };
    LpmKey::new(
        lpm_prefix_len(prefix),
        RuleData {
            family,
            proto: proto_code(protocol),
            dport: port.to_be(),
            addr: addr_bytes(addr),
        },
    )
}

pub(in crate::data_plane::xdp) fn geo_key(addr: IpAddr, prefix: u8) -> GeoKey {
    let family = if addr.is_ipv4() { 4 } else { 6 };
    LpmKey::new(
        lpm_prefix_len(prefix),
        GeoData {
            family,
            pad: [0; 3],
            addr: addr_bytes(addr),
        },
    )
}

pub(in crate::data_plane::xdp) fn trusted_key(addr: IpAddr, prefix: u8) -> TrustedKey {
    let family = if addr.is_ipv4() { 4 } else { 6 };
    LpmKey::new(
        lpm_prefix_len(prefix),
        TrustedData {
            family,
            pad: [0; 3],
            addr: addr_bytes(addr),
        },
    )
}

pub(in crate::data_plane::xdp) fn custom_rate_key(
    protocol: L4Protocol,
    port: u16,
) -> CustomRateKey {
    CustomRateKey {
        proto: proto_code(protocol),
        pad: 0,
        dport: port.to_be(),
    }
}

pub(in crate::data_plane::xdp) fn temp_ban_key(
    addr: IpAddr,
    prefix: u8,
    protocol: L4Protocol,
    port: u16,
) -> TempBanKey {
    LpmKey::new(
        lpm_prefix_len(prefix),
        TempBanData {
            family: if addr.is_ipv4() { 4 } else { 6 },
            proto: proto_code(protocol),
            dport: port.to_be(),
            addr: addr_bytes(addr),
        },
    )
}

pub(in crate::data_plane::xdp) fn rule_key_id(key: &RuleKey) -> RuleId {
    let data = key.data();
    (
        key.prefix_len(),
        data.family,
        data.proto,
        data.dport,
        data.addr,
    )
}

pub(in crate::data_plane::xdp) fn geo_key_id(key: &GeoKey) -> GeoId {
    let data = key.data();
    (key.prefix_len(), data.family, data.addr)
}

pub(in crate::data_plane::xdp) fn trusted_key_id(key: &TrustedKey) -> TrustedId {
    let data = key.data();
    (key.prefix_len(), data.family, data.addr)
}

pub(in crate::data_plane::xdp) fn trusted_key_cidr(key: &TrustedKey) -> String {
    let data = key.data();
    let prefix = key.prefix_len().saturating_sub(32);
    let addr = map_addr(data.family, data.addr);
    format!("{addr}/{prefix}")
}

pub(in crate::data_plane::xdp) fn custom_rate_key_id(key: &CustomRateKey) -> CustomRateId {
    (key.proto, key.dport)
}

pub(in crate::data_plane::xdp) fn temp_ban_key_id(key: &TempBanKey) -> TempBanId {
    let data = key.data();
    (
        key.prefix_len(),
        data.family,
        data.proto,
        data.dport,
        data.addr,
    )
}

pub(in crate::data_plane::xdp) fn lpm_prefix_len(prefix: u8) -> u32 {
    32 + u32::from(prefix)
}
