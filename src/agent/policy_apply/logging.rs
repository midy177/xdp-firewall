use crate::policy::model::{CompiledPolicy, PolicySnapshot};
use tracing::{debug, info};

pub(super) fn log_policy_snapshot_summary(
    policy: &str,
    expected_version: i64,
    snapshot: &PolicySnapshot,
) {
    let dynamic = &snapshot.dynamic_defense;
    info!(
        policy,
        expected_version,
        rules = snapshot.rules.len(),
        geo_countries = snapshot.geo_countries.len(),
        trusted_cidrs = snapshot.trusted_cidrs.len(),
        temp_bans = snapshot.temp_bans.len(),
        threat_sources = snapshot.threat_sources.len(),
        threat_prefixes = snapshot.threat_prefixes.len(),
        dynamic_rate_limits = snapshot.dynamic_rate_limits.len(),
        dynamic_defense_enabled = dynamic.enabled,
        ip_rate_limit_enabled = dynamic.ip_rate_limit_enabled,
        ip_packets_per_second = dynamic.ip_packets_per_second,
        ip_burst = dynamic.ip_burst,
        flood_enabled = dynamic.flood_enabled,
        flood_packets_per_second = dynamic.flood_packets_per_second,
        flood_burst = dynamic.flood_burst,
        flood_block_seconds = dynamic.flood_block_seconds,
        "received xDS policy snapshot"
    );
    if !snapshot.temp_bans.is_empty() {
        debug!(
            policy,
            expected_version,
            temp_bans = %snapshot_temp_ban_list(snapshot),
            temp_ban_count = snapshot.temp_bans.len(),
            "received xDS temporary ban list"
        );
    }
}

pub(super) fn log_compiled_policy_summary(
    policy: &str,
    expected_version: i64,
    compiled: &CompiledPolicy,
) {
    info!(
        policy,
        expected_version,
        compiled_version = compiled.version,
        rule_prefixes = compiled.rules.len(),
        geo_prefixes = compiled.geo_prefixes.len(),
        country_rules = compiled.country_rules.len(),
        trusted_prefixes = compiled.trusted_prefixes.len(),
        temp_bans = compiled.temp_bans.len(),
        threat_prefixes = compiled.threat_prefixes.len(),
        dynamic_rate_limits = compiled.dynamic_rate_limits.len(),
        "compiled xDS policy for XDP maps"
    );
    if !compiled.temp_bans.is_empty() {
        debug!(
            policy,
            expected_version,
            compiled_version = compiled.version,
            temp_bans = %compiled_temp_ban_list(compiled),
            temp_ban_count = compiled.temp_bans.len(),
            "compiled temporary ban list for XDP maps"
        );
    }
}

fn snapshot_temp_ban_list(snapshot: &PolicySnapshot) -> String {
    snapshot
        .temp_bans
        .iter()
        .map(|ban| {
            format!(
                "{}/{:?}/{}@{}",
                ban.cidr,
                ban.protocol,
                ban.port.unwrap_or(0),
                ban.expires_at
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn compiled_temp_ban_list(compiled: &CompiledPolicy) -> String {
    compiled
        .temp_bans
        .iter()
        .map(|ban| {
            format!(
                "{}/{}/{:?}/{}@{}",
                ban.addr, ban.prefix, ban.protocol, ban.port, ban.expires_at
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}
