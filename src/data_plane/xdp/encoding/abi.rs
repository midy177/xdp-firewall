use aya::{Pod, maps::lpm_trie::Key as LpmKey};

pub(in crate::data_plane::xdp) const ACTION_ALLOW: u8 = 1;
pub(in crate::data_plane::xdp) const ACTION_DENY: u8 = 2;
pub(in crate::data_plane::xdp) const PROTO_ANY: u8 = 0;
pub(in crate::data_plane::xdp) const PROTO_ICMP: u8 = 1;
pub(in crate::data_plane::xdp) const PROTO_TCP: u8 = 6;
pub(in crate::data_plane::xdp) const PROTO_UDP: u8 = 17;
pub(in crate::data_plane::xdp) const RULE_SOURCE_FIREWALL: u8 = 1;
pub(in crate::data_plane::xdp) const RULE_SOURCE_THREAT: u8 = 2;

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct RuleData {
    pub(in crate::data_plane::xdp) family: u8,
    pub(in crate::data_plane::xdp) proto: u8,
    pub(in crate::data_plane::xdp) dport: u16,
    pub(in crate::data_plane::xdp) addr: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct GeoData {
    pub(in crate::data_plane::xdp) family: u8,
    pub(in crate::data_plane::xdp) pad: [u8; 3],
    pub(in crate::data_plane::xdp) addr: [u8; 16],
}

pub(in crate::data_plane::xdp) type RuleKey = LpmKey<RuleData>;
pub(in crate::data_plane::xdp) type GeoKey = LpmKey<GeoData>;
pub(in crate::data_plane::xdp) type RuleId = (u32, u8, u8, u16, [u8; 16]);
pub(in crate::data_plane::xdp) type GeoId = (u32, u8, [u8; 16]);

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct TrustedData {
    pub(in crate::data_plane::xdp) family: u8,
    pub(in crate::data_plane::xdp) pad: [u8; 3],
    pub(in crate::data_plane::xdp) addr: [u8; 16],
}

pub(in crate::data_plane::xdp) type TrustedKey = LpmKey<TrustedData>;
pub(in crate::data_plane::xdp) type TrustedId = (u32, u8, [u8; 16]);

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct RuleValue {
    pub(in crate::data_plane::xdp) action: u8,
    pub(in crate::data_plane::xdp) source: u8,
    pub(in crate::data_plane::xdp) pad: [u8; 2],
    pub(in crate::data_plane::xdp) priority: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct GeoValue {
    pub(in crate::data_plane::xdp) country: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct CountryValue {
    pub(in crate::data_plane::xdp) action: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct DefenseValue {
    pub(in crate::data_plane::xdp) enabled: u8,
    pub(in crate::data_plane::xdp) ip_rate_limit_enabled: u8,
    pub(in crate::data_plane::xdp) flood_enabled: u8,
    pub(in crate::data_plane::xdp) pad: u8,
    pub(in crate::data_plane::xdp) ip_packets_per_second: u32,
    pub(in crate::data_plane::xdp) ip_burst: u32,
    pub(in crate::data_plane::xdp) flood_packets_per_second: u32,
    pub(in crate::data_plane::xdp) flood_burst: u32,
    pub(in crate::data_plane::xdp) flood_block_ns: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct CustomRateKey {
    pub(in crate::data_plane::xdp) proto: u8,
    pub(in crate::data_plane::xdp) pad: u8,
    pub(in crate::data_plane::xdp) dport: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct CustomRateValue {
    pub(in crate::data_plane::xdp) packets_per_second: u32,
    pub(in crate::data_plane::xdp) burst: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct TempBanData {
    pub(in crate::data_plane::xdp) family: u8,
    pub(in crate::data_plane::xdp) proto: u8,
    pub(in crate::data_plane::xdp) dport: u16,
    pub(in crate::data_plane::xdp) addr: [u8; 16],
}

pub(in crate::data_plane::xdp) type TempBanKey = LpmKey<TempBanData>;
pub(in crate::data_plane::xdp) type CustomRateId = (u8, u16);
pub(in crate::data_plane::xdp) type TempBanId = (u32, u8, u8, u16, [u8; 16]);

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct TempBanValue {
    pub(in crate::data_plane::xdp) expires_at_ns: u64,
}

#[derive(Debug, serde::Serialize)]
pub(in crate::data_plane::xdp) struct PinnedTempBanEntry {
    pub(in crate::data_plane::xdp) cidr: String,
    pub(in crate::data_plane::xdp) protocol: String,
    pub(in crate::data_plane::xdp) port: String,
    pub(in crate::data_plane::xdp) expires_at_ns: u64,
    pub(in crate::data_plane::xdp) remaining_seconds: i64,
    pub(in crate::data_plane::xdp) active: bool,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct TrustedValue {
    pub(in crate::data_plane::xdp) value: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::data_plane::xdp) struct DropConfigValue {
    pub(in crate::data_plane::xdp) value: u8,
}

unsafe impl Pod for RuleData {}
unsafe impl Pod for GeoData {}
unsafe impl Pod for TrustedData {}
unsafe impl Pod for RuleValue {}
unsafe impl Pod for GeoValue {}
unsafe impl Pod for CountryValue {}
unsafe impl Pod for DefenseValue {}
unsafe impl Pod for CustomRateKey {}
unsafe impl Pod for CustomRateValue {}
unsafe impl Pod for TempBanData {}
unsafe impl Pod for TempBanValue {}
unsafe impl Pod for TrustedValue {}
unsafe impl Pod for DropConfigValue {}
