use super::*;
use crate::policy::model::{
    L4Protocol, RuleAction, XdpPrefixRule, XdpRuleSource, XdpTempBan, XdpTrustedPrefix,
};

#[test]
fn compact_trusted_prefixes_removes_only_contained_prefixes() {
    let compacted = compact_trusted_prefixes(&[
        XdpTrustedPrefix {
            addr: "172.30.133.54".parse().unwrap(),
            prefix: 32,
        },
        XdpTrustedPrefix {
            addr: "172.30.0.0".parse().unwrap(),
            prefix: 16,
        },
        XdpTrustedPrefix {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 24,
        },
        XdpTrustedPrefix {
            addr: "10.0.1.0".parse().unwrap(),
            prefix: 24,
        },
        XdpTrustedPrefix {
            addr: "fd00::1".parse().unwrap(),
            prefix: 128,
        },
        XdpTrustedPrefix {
            addr: "fd00::".parse().unwrap(),
            prefix: 64,
        },
    ]);

    assert_eq!(
        compacted,
        vec![
            XdpTrustedPrefix {
                addr: "172.30.0.0".parse().unwrap(),
                prefix: 16,
            },
            XdpTrustedPrefix {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 24,
            },
            XdpTrustedPrefix {
                addr: "10.0.1.0".parse().unwrap(),
                prefix: 24,
            },
            XdpTrustedPrefix {
                addr: "fd00::".parse().unwrap(),
                prefix: 64,
            },
        ]
    );
}

#[test]
fn compact_temp_bans_drops_shorter_lived_covered_prefixes() {
    let now = chrono::Utc::now().naive_utc();
    let compacted = compact_temp_bans(&[
        XdpTempBan {
            addr: "203.0.113.10".parse().unwrap(),
            prefix: 32,
            protocol: L4Protocol::Tcp,
            port: 443,
            expires_at: now + chrono::Duration::seconds(60),
        },
        XdpTempBan {
            addr: "203.0.113.0".parse().unwrap(),
            prefix: 24,
            protocol: L4Protocol::Tcp,
            port: 443,
            expires_at: now + chrono::Duration::seconds(300),
        },
        XdpTempBan {
            addr: "203.0.113.20".parse().unwrap(),
            prefix: 32,
            protocol: L4Protocol::Tcp,
            port: 443,
            expires_at: now + chrono::Duration::seconds(600),
        },
        XdpTempBan {
            addr: "203.0.113.10".parse().unwrap(),
            prefix: 32,
            protocol: L4Protocol::Udp,
            port: 443,
            expires_at: now + chrono::Duration::seconds(60),
        },
    ]);

    assert_eq!(compacted.len(), 3);
    assert!(compacted.iter().any(|ban| {
        ban.addr.to_string() == "203.0.113.0" && ban.prefix == 24 && ban.protocol == L4Protocol::Tcp
    }));
    assert!(compacted.iter().any(|ban| {
        ban.addr.to_string() == "203.0.113.20"
            && ban.prefix == 32
            && ban.protocol == L4Protocol::Tcp
    }));
    assert!(compacted.iter().any(|ban| {
        ban.addr.to_string() == "203.0.113.10"
            && ban.prefix == 32
            && ban.protocol == L4Protocol::Udp
    }));
}

#[test]
fn deny_rule_matching_local_cidr_detects_covering_cidr() {
    let local_cidrs = vec![
        LocalInterfaceCidr {
            ip: "172.30.133.54".parse().unwrap(),
            prefix: 20,
        },
        LocalInterfaceCidr {
            ip: "fd00::1234".parse().unwrap(),
            prefix: 64,
        },
    ];
    let deny_rule = XdpPrefixRule {
        addr: "172.30.0.0".parse().unwrap(),
        prefix: 16,
        priority: 10,
        action: RuleAction::Deny,
        protocol: L4Protocol::Any,
        port: 0,
        source: XdpRuleSource::FirewallRule,
    };
    let allow_rule = XdpPrefixRule {
        action: RuleAction::Allow,
        ..deny_rule
    };
    let unrelated_deny = XdpPrefixRule {
        addr: "10.0.0.0".parse().unwrap(),
        prefix: 8,
        ..deny_rule
    };

    assert_eq!(
        deny_rule_matching_local_cidr(&deny_rule, &local_cidrs),
        Some(LocalInterfaceCidr {
            ip: "172.30.133.54".parse().unwrap(),
            prefix: 20,
        })
    );
    assert_eq!(
        deny_rule_matching_local_cidr(&allow_rule, &local_cidrs),
        None
    );
    assert_eq!(
        deny_rule_matching_local_cidr(&unrelated_deny, &local_cidrs),
        None
    );
}

#[test]
fn temp_ban_matching_local_cidr_detects_covering_cidr() {
    let local_cidrs = vec![LocalInterfaceCidr {
        ip: "203.0.113.10".parse().unwrap(),
        prefix: 24,
    }];
    let ban = XdpTempBan {
        addr: "203.0.113.0".parse().unwrap(),
        prefix: 24,
        protocol: L4Protocol::Tcp,
        port: 443,
        expires_at: chrono::Utc::now().naive_utc() + chrono::Duration::seconds(300),
    };
    let unrelated = XdpTempBan {
        addr: "198.51.100.0".parse().unwrap(),
        prefix: 24,
        ..ban
    };

    assert_eq!(
        temp_ban_matching_local_cidr(ban, &local_cidrs),
        Some(LocalInterfaceCidr {
            ip: "203.0.113.10".parse().unwrap(),
            prefix: 24,
        })
    );
    assert_eq!(temp_ban_matching_local_cidr(unrelated, &local_cidrs), None);
}

#[test]
fn format_local_interface_cidrs_uses_ip_slash_prefix() {
    assert_eq!(
        format_local_interface_cidrs(&[
            LocalInterfaceCidr {
                ip: "172.30.133.54".parse().unwrap(),
                prefix: 20,
            },
            LocalInterfaceCidr {
                ip: "fd00::1234".parse().unwrap(),
                prefix: 64,
            },
        ]),
        "172.30.133.54/20,fd00::1234/64"
    );
}
