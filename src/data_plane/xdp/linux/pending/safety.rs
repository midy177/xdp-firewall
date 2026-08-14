use super::super::*;
use tracing::error;

pub(super) fn temp_ban_matches_local_interface(manager: &LinuxXdpManager, ban: XdpTempBan) -> bool {
    let Some(local) = temp_ban_matching_local_cidr(ban, &manager.local_interface_cidrs) else {
        return false;
    };
    error!(
        interface = %manager.interface,
        local_ip = %local.ip,
        local_prefix = local.prefix,
        addr = %ban.addr,
        prefix = ban.prefix,
        protocol = ?ban.protocol,
        port = ban.port,
        "refusing to write temporary ban that matches the agent interface IP"
    );
    true
}

pub(super) fn deny_rule_matches_local_interface(
    manager: &LinuxXdpManager,
    rule: &XdpPrefixRule,
) -> bool {
    let Some(local) = deny_rule_matching_local_cidr(rule, &manager.local_interface_cidrs) else {
        return false;
    };
    error!(
        interface = %manager.interface,
        local_ip = %local.ip,
        local_prefix = local.prefix,
        addr = %rule.addr,
        prefix = rule.prefix,
        protocol = ?rule.protocol,
        port = rule.port,
        source = ?rule.source,
        "refusing to write XDP deny rule that matches the agent interface IP"
    );
    true
}
