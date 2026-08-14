use super::super::*;
use super::safety::deny_rule_matches_local_interface;
use std::collections::HashSet;
use tracing::warn;

pub(super) fn pending_rules<'a>(
    manager: &LinuxXdpManager,
    policy: &'a CompiledPolicy,
) -> (HashSet<RuleId>, Vec<(RuleKey, &'a XdpPrefixRule)>) {
    let mut ids = HashSet::new();
    let mut pending = Vec::new();
    for rule in ordered_policy_rules(policy) {
        collect_rule(manager, rule, &mut ids, &mut pending);
    }
    (ids, pending)
}

fn ordered_policy_rules(policy: &CompiledPolicy) -> Vec<&XdpPrefixRule> {
    let mut rules = policy
        .threat_prefixes
        .iter()
        .chain(policy.rules.iter())
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| rule_source_order(left.source).cmp(&rule_source_order(right.source)))
    });
    rules
}

fn collect_rule<'a>(
    manager: &LinuxXdpManager,
    rule: &'a XdpPrefixRule,
    ids: &mut HashSet<RuleId>,
    pending: &mut Vec<(RuleKey, &'a XdpPrefixRule)>,
) {
    if deny_rule_matches_local_interface(manager, rule) {
        return;
    }
    let key = rule_key(rule.addr, rule.prefix, rule.protocol, rule.port);
    if ids.insert(rule_key_id(&key)) {
        pending.push((key, rule));
    } else {
        warn!(
            addr = %rule.addr,
            prefix = rule.prefix,
            protocol = ?rule.protocol,
            port = rule.port,
            source = ?rule.source,
            "skipping duplicate XDP rule key; first matching key remains active"
        );
    }
}
