use super::{cidr_fingerprint, compact_covered_cidrs};
use crate::policy::model::{PolicySnapshot, TrustedCidrPolicy};
use ipnet::IpNet;
use std::collections::HashSet;
use tracing::debug;

pub(in crate::control_plane::xds) struct RuntimeTrustedCidrSnapshot {
    pub(in crate::control_plane::xds) configured: Vec<IpNet>,
    pub(in crate::control_plane::xds) all: Vec<IpNet>,
    pub(in crate::control_plane::xds) inject: Vec<IpNet>,
    pub(in crate::control_plane::xds) covered: usize,
}

pub(in crate::control_plane::xds) fn debug_runtime_trusted_cidrs(
    snapshot: &RuntimeTrustedCidrSnapshot,
) {
    if snapshot.all.is_empty() {
        return;
    }
    debug!(
        configured_runtime_trusted_cidrs = %cidr_fingerprint(&snapshot.configured),
        configured_runtime_trusted_cidr_count = snapshot.configured.len(),
        effective_runtime_trusted_cidrs = %cidr_fingerprint(&snapshot.all),
        effective_runtime_trusted_cidr_count = snapshot.all.len(),
        injected_runtime_trusted_cidrs = %cidr_fingerprint(&snapshot.inject),
        injected_runtime_trusted_cidr_count = snapshot.inject.len(),
        covered_runtime_trusted_cidr_count = snapshot.covered,
        "prepared runtime trusted CIDRs for xDS policy snapshot"
    );
}

pub(in crate::control_plane::xds) fn compact_runtime_trusted_cidrs_with_snapshot(
    snapshot: &PolicySnapshot,
    runtime: RuntimeTrustedCidrSnapshot,
) -> RuntimeTrustedCidrSnapshot {
    if runtime.all.is_empty() {
        return runtime;
    }

    let static_cidrs = snapshot
        .trusted_cidrs
        .iter()
        .map(|trusted| trusted.cidr)
        .collect::<Vec<_>>();
    if static_cidrs.is_empty() {
        return runtime;
    }

    let mut combined = static_cidrs.clone();
    combined.extend(runtime.all.iter().copied());
    let compacted = compact_covered_cidrs(&combined);
    let effective = compacted
        .cidrs
        .iter()
        .copied()
        .filter(|cidr| !static_cidrs.contains(cidr))
        .collect::<Vec<_>>();
    let effective_len = effective.len();

    RuntimeTrustedCidrSnapshot {
        configured: runtime.configured,
        all: effective.clone(),
        inject: effective,
        covered: runtime.covered + runtime.all.len().saturating_sub(effective_len),
    }
}

pub(in crate::control_plane::xds) fn inject_runtime_trusted_cidrs(
    snapshot: &mut PolicySnapshot,
    cidrs: Vec<IpNet>,
) {
    let mut seen = snapshot
        .trusted_cidrs
        .iter()
        .map(|trusted| trusted.cidr)
        .collect::<HashSet<_>>();
    let mut added = 0_usize;
    for cidr in cidrs {
        if seen.insert(cidr) {
            snapshot.trusted_cidrs.push(TrustedCidrPolicy {
                cidr,
                comment: Some("runtime xDS trusted CIDR".to_string()),
            });
            added += 1;
        }
    }
    if added > 0 {
        debug!(
            added,
            total_trusted_cidrs = snapshot.trusted_cidrs.len(),
            "injected runtime trusted CIDRs into xDS policy snapshot"
        );
    }
}
