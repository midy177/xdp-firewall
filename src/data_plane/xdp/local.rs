use std::net::IpAddr;

mod compaction;
mod interface;

pub(super) use compaction::{
    compact_temp_bans, compact_trusted_prefixes, deny_rule_matching_local_cidr,
    temp_ban_matching_local_cidr,
};
#[cfg(target_os = "linux")]
pub(super) use interface::local_interface_cidrs;
pub(super) use interface::{LocalInterfaceCidr, format_local_interface_cidrs};

fn prefix_contains_ip(addr: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    if addr.is_ipv4() != ip.is_ipv4() {
        return false;
    }
    ipnet::IpNet::new(addr, prefix)
        .ok()
        .is_some_and(|net| net.trunc().contains(&ip))
}
