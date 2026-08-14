use super::{LocalInterfaceCidr, prefix_contains_ip};
use crate::policy::model::{RuleAction, XdpPrefixRule, XdpTempBan, XdpTrustedPrefix};

pub(in crate::data_plane::xdp) fn compact_trusted_prefixes(
    prefixes: &[XdpTrustedPrefix],
) -> Vec<XdpTrustedPrefix> {
    let mut compacted = Vec::with_capacity(prefixes.len());
    for (index, prefix) in prefixes.iter().enumerate() {
        if prefixes.iter().enumerate().any(|(other_index, other)| {
            other_index != index && trusted_prefix_covers(*other, *prefix)
        }) {
            continue;
        }
        compacted.push(*prefix);
    }
    compacted
}

pub(in crate::data_plane::xdp) fn compact_temp_bans(bans: &[XdpTempBan]) -> Vec<XdpTempBan> {
    let mut compacted = Vec::with_capacity(bans.len());
    for (index, ban) in bans.iter().enumerate() {
        if bans.iter().enumerate().any(|(other_index, other)| {
            other_index != index && temp_ban_covers_or_supersedes(*other, *ban)
        }) {
            continue;
        }
        compacted.push(*ban);
    }
    compacted
}

pub(in crate::data_plane::xdp) fn deny_rule_matching_local_cidr(
    rule: &XdpPrefixRule,
    local_cidrs: &[LocalInterfaceCidr],
) -> Option<LocalInterfaceCidr> {
    if rule.action != RuleAction::Deny {
        return None;
    }
    local_cidrs
        .iter()
        .copied()
        .find(|local| prefix_contains_ip(rule.addr, rule.prefix, local.ip))
}

pub(in crate::data_plane::xdp) fn temp_ban_matching_local_cidr(
    ban: XdpTempBan,
    local_cidrs: &[LocalInterfaceCidr],
) -> Option<LocalInterfaceCidr> {
    local_cidrs
        .iter()
        .copied()
        .find(|local| prefix_contains_ip(ban.addr, ban.prefix, local.ip))
}

fn trusted_prefix_covers(cover: XdpTrustedPrefix, prefix: XdpTrustedPrefix) -> bool {
    if cover == prefix || cover.prefix > prefix.prefix {
        return false;
    }
    let Some(cover) = trusted_prefix_ipnet(cover) else {
        return false;
    };
    let Some(prefix) = trusted_prefix_ipnet(prefix) else {
        return false;
    };
    match (cover, prefix) {
        (ipnet::IpNet::V4(cover), ipnet::IpNet::V4(prefix)) => cover.contains(&prefix.network()),
        (ipnet::IpNet::V6(cover), ipnet::IpNet::V6(prefix)) => cover.contains(&prefix.network()),
        _ => false,
    }
}

fn trusted_prefix_ipnet(prefix: XdpTrustedPrefix) -> Option<ipnet::IpNet> {
    ipnet::IpNet::new(prefix.addr, prefix.prefix)
        .ok()
        .map(|net| net.trunc())
}

fn temp_ban_covers_or_supersedes(cover: XdpTempBan, ban: XdpTempBan) -> bool {
    if cover.protocol != ban.protocol || cover.port != ban.port {
        return false;
    }
    if cover.addr == ban.addr && cover.prefix == ban.prefix {
        return cover.expires_at > ban.expires_at;
    }
    if cover.prefix > ban.prefix || cover.expires_at < ban.expires_at {
        return false;
    }
    let Some(cover) = temp_ban_ipnet(cover) else {
        return false;
    };
    let Some(ban) = temp_ban_ipnet(ban) else {
        return false;
    };
    match (cover, ban) {
        (ipnet::IpNet::V4(cover), ipnet::IpNet::V4(ban)) => cover.contains(&ban.network()),
        (ipnet::IpNet::V6(cover), ipnet::IpNet::V6(ban)) => cover.contains(&ban.network()),
        _ => false,
    }
}

fn temp_ban_ipnet(ban: XdpTempBan) -> Option<ipnet::IpNet> {
    ipnet::IpNet::new(ban.addr, ban.prefix)
        .ok()
        .map(|net| net.trunc())
}
