#[cfg(target_os = "linux")]
use crate::{data_plane::xdp, intelligence::geo};
use serde::Serialize;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize)]
pub struct DropEventLine {
    pub time: String,
    pub event_time_ns: u64,
    pub cpu: u32,
    pub reason: &'static str,
    pub src: IpAddr,
    pub family: u8,
    pub proto: String,
    pub dport: u16,
    pub country: Option<String>,
    pub action: &'static str,
}

impl DropEventLine {
    #[must_use]
    pub fn to_line(&self) -> String {
        let country = self.country.as_deref().unwrap_or("-");
        format!(
            "time={} event_time_ns={} cpu={} reason={} src={} family={} proto={} dport={} country={} action={}",
            self.time,
            self.event_time_ns,
            self.cpu,
            self.reason,
            self.src,
            self.family,
            self.proto,
            self.dport,
            country,
            self.action
        )
    }
}

#[cfg(target_os = "linux")]
pub fn parse_drop_event(cpu: u32, bytes: &[u8]) -> Option<DropEventLine> {
    if bytes.len() < 36 {
        return None;
    }
    let event_time_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let reason = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let family = bytes[12];
    let proto = bytes[13];
    let dport = u16::from_be_bytes(bytes[14..16].try_into().ok()?);
    let mut addr = [0_u8; 16];
    addr.copy_from_slice(&bytes[16..32]);
    let country = u16::from_ne_bytes(bytes[32..34].try_into().ok()?);
    let action = bytes[34];
    let source = bytes[35];
    let src = match family {
        4 => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
        6 => IpAddr::V6(Ipv6Addr::from(addr)),
        _ => return None,
    };
    Some(DropEventLine {
        time: chrono::Utc::now().to_rfc3339(),
        event_time_ns,
        cpu,
        reason: reason_label(reason, source),
        src,
        family,
        proto: proto_label(proto).to_string(),
        dport,
        country: decode_country(country),
        action: action_label(action),
    })
}

#[cfg(target_os = "linux")]
fn reason_label(reason: u32, source: u8) -> &'static str {
    match reason {
        xdp::STAT_RULE_DROP if source == 2 => "threat_intel",
        xdp::STAT_RULE_DROP => "firewall_rule",
        xdp::STAT_GEO_DROP => "country",
        xdp::STAT_TEMP_BAN_DROP => "temporary_ban",
        xdp::STAT_RATE_DROP => "dynamic_defense.ip_rate_limit",
        xdp::STAT_FLOOD_DROP => "dynamic_defense.flood",
        xdp::STAT_CUSTOM_RATE_DROP => "dynamic_defense.custom_rate_limit",
        xdp::STAT_PARSE_DROP => "parse_error",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn proto_label(proto: u8) -> &'static str {
    match proto {
        0 => "any",
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

#[cfg(target_os = "linux")]
fn action_label(action: u8) -> &'static str {
    match action {
        1 => "allow",
        2 => "deny",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn decode_country(country: u16) -> Option<String> {
    if country == 0 {
        return None;
    }
    let first = ((country >> 8) & 0xff) as u8;
    let second = (country & 0xff) as u8;
    let code = String::from_utf8(vec![first, second]).ok()?;
    geo::normalize_country(&code).ok()
}
