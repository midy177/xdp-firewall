use crate::{
    data_plane::xdp,
    policy::{
        compile,
        model::{DEFAULT_POLICY_NAME, PolicySnapshot},
    },
};
use anyhow::Result;
use tracing::info;

mod control_plane_trust;
mod logging;

use control_plane_trust::add_control_plane_trusted_cidrs;
use logging::{log_compiled_policy_summary, log_policy_snapshot_summary};

pub(super) fn apply_latest(
    xdp: &mut xdp::XdpManager,
    mut snapshot: PolicySnapshot,
    control_url: &str,
    expected_version: i64,
) -> Result<i64> {
    let policy = DEFAULT_POLICY_NAME;
    add_control_plane_trusted_cidrs(&mut snapshot, control_url)?;
    log_policy_snapshot_summary(policy, expected_version, &snapshot);
    let compiled = compile::compile_policy(&snapshot)?;
    log_compiled_policy_summary(policy, expected_version, &compiled);
    xdp.apply(&compiled)?;
    info!(
        policy,
        expected_version,
        applied_version = compiled.version,
        "applied firewall policy"
    );
    Ok(compiled.version)
}
