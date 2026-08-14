use crate::cli::AgentOfflineMode;
use crate::{
    data_plane::xdp,
    policy::model::{CompiledPolicy, XdpDynamicDefense},
};
use anyhow::{Context, Result};

#[derive(Debug, Default)]
pub(super) struct OfflinePolicyState {
    pub(super) consecutive_failures: u32,
    pub(super) rules_unloaded: bool,
}

impl OfflinePolicyState {
    pub(super) fn record_control_plane_failure(&mut self) -> u32 {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.consecutive_failures
    }

    pub(super) fn record_control_plane_healthy(&mut self) {
        self.consecutive_failures = 0;
    }

    pub(super) fn record_policy_applied(&mut self) {
        self.consecutive_failures = 0;
        self.rules_unloaded = false;
    }

    pub(super) fn should_unload_rules(
        &self,
        offline_mode: AgentOfflineMode,
        failure_limit: u32,
    ) -> bool {
        offline_mode == AgentOfflineMode::UnloadRules
            && !self.rules_unloaded
            && self.consecutive_failures >= failure_limit
    }
}

pub(super) fn unload_firewall_rules_for_offline_mode(
    xdp: &mut xdp::XdpManager,
    previous_version: i64,
) -> Result<()> {
    let empty_policy = CompiledPolicy {
        version: previous_version.max(0),
        trusted_prefixes: Vec::new(),
        rules: Vec::new(),
        country_rules: Vec::new(),
        temp_bans: Vec::new(),
        dynamic_defense: XdpDynamicDefense::default(),
        dynamic_rate_limits: Vec::new(),
        geo_prefixes: Vec::new(),
        threat_prefixes: Vec::new(),
    };
    xdp.apply(&empty_policy)
        .context("failed to unload XDP firewall rules for offline mode")
}
