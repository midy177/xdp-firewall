use super::super::*;
use std::collections::HashSet;
use tracing::warn;

pub(super) fn pending_custom_rate_limits(
    limits: &[XdpDynamicRateLimit],
) -> (
    HashSet<CustomRateId>,
    Vec<(CustomRateKey, &XdpDynamicRateLimit)>,
) {
    let mut ids = HashSet::new();
    let mut pending = Vec::new();
    for limit in limits {
        let key = custom_rate_key(limit.protocol, limit.port);
        let id = custom_rate_key_id(&key);
        if ids.insert(id) {
            pending.push((key, limit));
        } else {
            warn!(
                protocol = ?limit.protocol,
                port = limit.port,
                "skipping duplicate custom dynamic rate-limit key; first matching key remains active"
            );
        }
    }
    (ids, pending)
}

pub(super) fn pending_trusted_keys(
    prefixes: &[XdpTrustedPrefix],
) -> (HashSet<TrustedId>, Vec<TrustedKey>) {
    let mut ids = HashSet::new();
    let mut pending = Vec::new();
    let trusted_prefixes = compact_trusted_prefixes(prefixes);
    for prefix in &trusted_prefixes {
        let key = trusted_key(prefix.addr, prefix.prefix);
        let id = trusted_key_id(&key);
        if ids.insert(id) {
            pending.push(key);
        }
    }
    (ids, pending)
}

pub(super) fn pending_geo_prefixes(
    prefixes: &[XdpGeoPrefix],
) -> (HashSet<GeoId>, Vec<(GeoKey, &XdpGeoPrefix)>) {
    let mut ids = HashSet::new();
    let mut pending = Vec::new();
    for prefix in prefixes {
        let key = geo_key(prefix.addr, prefix.prefix);
        let id = geo_key_id(&key);
        if ids.insert(id) {
            pending.push((key, prefix));
        }
    }
    (ids, pending)
}

pub(super) fn pending_country_rules(
    rules: &[XdpCountryRule],
) -> (HashSet<u32>, Vec<(u32, &XdpCountryRule)>) {
    let mut ids = HashSet::new();
    let mut pending = Vec::new();
    for country in rules {
        let key = country_key(country.country);
        if ids.insert(key) {
            pending.push((key, country));
        }
    }
    (ids, pending)
}
