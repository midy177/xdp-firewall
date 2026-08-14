use super::*;
use std::collections::HashSet;
use tracing::info;

mod rules;
mod safety;
mod sets;
mod temp_bans;

use rules::pending_rules;
use sets::{
    pending_country_rules, pending_custom_rate_limits, pending_geo_prefixes, pending_trusted_keys,
};
use temp_bans::pending_temp_bans;

pub(super) struct PendingPolicyKeys<'a> {
    pub(super) rule_ids: HashSet<RuleId>,
    pub(super) rules: Vec<(RuleKey, &'a XdpPrefixRule)>,
    pub(super) geo_ids: HashSet<GeoId>,
    pub(super) geo_prefixes: Vec<(GeoKey, &'a XdpGeoPrefix)>,
    pub(super) trusted_ids: HashSet<TrustedId>,
    pub(super) trusted_keys: Vec<TrustedKey>,
    pub(super) country_ids: HashSet<u32>,
    pub(super) country_rules: Vec<(u32, &'a XdpCountryRule)>,
    pub(super) custom_rate_ids: HashSet<CustomRateId>,
    pub(super) custom_rate_limits: Vec<(CustomRateKey, &'a XdpDynamicRateLimit)>,
    pub(super) temp_ban_ids: HashSet<TempBanId>,
    pub(super) temp_bans: Vec<(TempBanKey, XdpTempBan)>,
}

pub(super) fn build_pending_policy_keys<'a>(
    manager: &LinuxXdpManager,
    policy: &'a CompiledPolicy,
    wall_now: chrono::NaiveDateTime,
) -> PendingPolicyKeys<'a> {
    let (temp_ban_ids, temp_bans) = pending_temp_bans(manager, &policy.temp_bans, wall_now);
    let (custom_rate_ids, custom_rate_limits) =
        pending_custom_rate_limits(&policy.dynamic_rate_limits);
    let (trusted_ids, trusted_keys) = pending_trusted_keys(&policy.trusted_prefixes);
    let (rule_ids, rules) = pending_rules(manager, policy);
    let (geo_ids, geo_prefixes) = pending_geo_prefixes(&policy.geo_prefixes);
    let (country_ids, country_rules) = pending_country_rules(&policy.country_rules);

    PendingPolicyKeys {
        rule_ids,
        rules,
        geo_ids,
        geo_prefixes,
        trusted_ids,
        trusted_keys,
        country_ids,
        country_rules,
        custom_rate_ids,
        custom_rate_limits,
        temp_ban_ids,
        temp_bans,
    }
}

pub(super) fn log_written_trusted_cidrs(keys: &[TrustedKey]) {
    if keys.is_empty() {
        return;
    }
    let mut cidrs = keys.iter().map(trusted_key_cidr).collect::<Vec<_>>();
    cidrs.sort();
    info!(
        trusted_cidrs = %cidrs.join(","),
        trusted_cidr_count = cidrs.len(),
        "wrote trusted CIDRs to XDP map"
    );
}
