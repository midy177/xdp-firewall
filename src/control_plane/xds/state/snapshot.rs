use super::{TempBanCleanup, latest_version};
use crate::policy::{
    firewall,
    model::{DEFAULT_POLICY_NAME, PolicySnapshot},
};
use anyhow::Result;
use sea_orm::DatabaseConnection;

use super::super::{
    proto::PolicyUpdate,
    runtime_cidrs::{
        RuntimeTrustedCidrSnapshot, RuntimeTrustedCidrs, cidr_fingerprint,
        compact_runtime_trusted_cidrs_with_snapshot, debug_runtime_trusted_cidrs,
        inject_runtime_trusted_cidrs,
    },
};

pub(in crate::control_plane::xds) async fn build_policy_update(
    db: &DatabaseConnection,
    current_version: i64,
    current_runtime_fingerprint: Option<&str>,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
    temp_ban_cleanup: &TempBanCleanup,
    supports_external_geo_prefixes: bool,
) -> Result<Option<(PolicyUpdate, String)>> {
    temp_ban_cleanup.maybe_run(db).await?;
    let version = latest_version(db).await?;
    let runtime_cidrs = runtime_trusted_cidrs.current_snapshot().await;
    let runtime_fingerprint = cidr_fingerprint(&runtime_cidrs.all);
    if policy_update_unchanged(
        version,
        current_version,
        runtime_trusted_cidrs,
        current_runtime_fingerprint,
        &runtime_fingerprint,
    ) {
        return Ok(None);
    }
    let snapshot = load_policy_snapshot(db, runtime_cidrs, supports_external_geo_prefixes).await?;
    Ok(Some((
        policy_update(version, snapshot, supports_external_geo_prefixes)?,
        runtime_fingerprint,
    )))
}

pub(in crate::control_plane::xds) async fn load_xds_snapshot(
    db: &DatabaseConnection,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
    include_geo_prefixes: bool,
) -> Result<(PolicySnapshot, String)> {
    let runtime_cidrs = runtime_trusted_cidrs.current_snapshot().await;
    let runtime_fingerprint = cidr_fingerprint(&runtime_cidrs.all);
    let snapshot = load_policy_snapshot(db, runtime_cidrs, !include_geo_prefixes).await?;
    Ok((snapshot, runtime_fingerprint))
}

fn policy_update_unchanged(
    version: i64,
    current_version: i64,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
    current_runtime_fingerprint: Option<&str>,
    runtime_fingerprint: &str,
) -> bool {
    version <= current_version
        && (!runtime_trusted_cidrs.enabled()
            || current_runtime_fingerprint == Some(runtime_fingerprint))
}

async fn load_policy_snapshot(
    db: &DatabaseConnection,
    runtime_cidrs: RuntimeTrustedCidrSnapshot,
    external_geo_prefixes: bool,
) -> Result<PolicySnapshot> {
    let mut snapshot = if external_geo_prefixes {
        firewall::load_policy_without_geo_prefixes(db, DEFAULT_POLICY_NAME).await?
    } else {
        firewall::load_policy(db, DEFAULT_POLICY_NAME).await?
    };
    let runtime_cidrs = compact_runtime_trusted_cidrs_with_snapshot(&snapshot, runtime_cidrs);
    debug_runtime_trusted_cidrs(&runtime_cidrs);
    inject_runtime_trusted_cidrs(&mut snapshot, runtime_cidrs.inject);
    Ok(snapshot)
}

fn policy_update(
    version: i64,
    snapshot: PolicySnapshot,
    external_geo_prefixes: bool,
) -> Result<PolicyUpdate> {
    let geo_prefix_version = if external_geo_prefixes { version } else { 0 };
    Ok(PolicyUpdate {
        version,
        policy_json: serde_json::to_string(&snapshot)?,
        drop_monitor_enabled: false,
        external_geo_prefixes,
        geo_prefix_version,
    })
}
