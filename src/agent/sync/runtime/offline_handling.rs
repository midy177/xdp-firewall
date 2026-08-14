use super::{AgentRuntime, drop_monitor, offline, xdp};
use crate::agent::offline::unload_firewall_rules_for_offline_mode;
use crate::cli::AgentArgs;
use anyhow::Result;
use tokio::time;
use tracing::warn;

impl AgentRuntime {
    pub(super) async fn handle_control_plane_failure_and_wait(
        &mut self,
        details: &str,
    ) -> Result<()> {
        handle_control_plane_failure(
            &mut self.offline,
            &mut self.xdp,
            &mut self.drop_monitor,
            &self.args,
            &mut self.applied_version,
            details,
        )?;
        time::sleep(self.reconnect_delay).await;
        Ok(())
    }
}

fn handle_control_plane_failure(
    offline: &mut offline::OfflinePolicyState,
    xdp: &mut xdp::XdpManager,
    drop_monitor: &mut drop_monitor::DropMonitorHandle,
    args: &AgentArgs,
    applied_version: &mut i64,
    details: &str,
) -> Result<()> {
    let failures = offline.record_control_plane_failure();
    warn!(
        consecutive_failures = failures,
        failure_limit = args.offline_failure_limit,
        offline_mode = %args.offline_mode.as_str(),
        error = %details,
        "xDS/API connectivity failure recorded"
    );
    if offline.should_unload_rules(args.offline_mode, args.offline_failure_limit) {
        drop_monitor::disable(xdp, drop_monitor);
        unload_firewall_rules_for_offline_mode(xdp, *applied_version)?;
        *applied_version = -1;
        offline.rules_unloaded = true;
        warn!(
            consecutive_failures = failures,
            offline_mode = %args.offline_mode.as_str(),
            "agent entered offline mode; unloaded XDP firewall rules and will force a full policy reload after reconnect"
        );
    }
    Ok(())
}
