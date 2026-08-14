use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod abi;
mod codes;
mod keys;

pub(in crate::data_plane::xdp) use abi::*;
pub(in crate::data_plane::xdp) use codes::{
    action_code, proto_code, protocol_name, rule_source_code,
};
pub(in crate::data_plane::xdp) use keys::{
    country_key, custom_rate_key, custom_rate_key_id, geo_key, geo_key_id, rule_key, rule_key_id,
    rule_source_order, temp_ban_key, temp_ban_key_id, trusted_key, trusted_key_cidr,
    trusted_key_id,
};

pub(in crate::data_plane::xdp) fn map_addr(family: u8, addr: [u8; 16]) -> IpAddr {
    match family {
        4 => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
        6 => IpAddr::V6(Ipv6Addr::from(addr)),
        _ => IpAddr::V6(Ipv6Addr::from(addr)),
    }
}

pub(in crate::data_plane::xdp) fn addr_bytes(addr: IpAddr) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    match addr {
        IpAddr::V4(ip) => bytes[..4].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => bytes.copy_from_slice(&ip.octets()),
    }
    bytes
}
