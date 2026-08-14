use super::{ACTION_ALLOW, ACTION_DENY, PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::policy::model::{L4Protocol, RuleAction, XdpRuleSource};

use super::{RULE_SOURCE_FIREWALL, RULE_SOURCE_THREAT};

pub(in crate::data_plane::xdp) fn action_code(action: RuleAction) -> u8 {
    match action {
        RuleAction::Allow => ACTION_ALLOW,
        RuleAction::Deny => ACTION_DENY,
    }
}

pub(in crate::data_plane::xdp) fn rule_source_code(source: XdpRuleSource) -> u8 {
    match source {
        XdpRuleSource::FirewallRule => RULE_SOURCE_FIREWALL,
        XdpRuleSource::ThreatIntel => RULE_SOURCE_THREAT,
    }
}

pub(in crate::data_plane::xdp) fn proto_code(protocol: L4Protocol) -> u8 {
    match protocol {
        L4Protocol::Any => PROTO_ANY,
        L4Protocol::Tcp => PROTO_TCP,
        L4Protocol::Udp => PROTO_UDP,
        L4Protocol::Icmp => PROTO_ICMP,
    }
}

pub(in crate::data_plane::xdp) fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        PROTO_ANY => "any",
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        PROTO_ICMP => "icmp",
        _ => "unknown",
    }
}
