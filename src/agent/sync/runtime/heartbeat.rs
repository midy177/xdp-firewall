use super::{AgentRuntime, xds};
use anyhow::Result;

impl AgentRuntime {
    pub(super) async fn report_ok_heartbeat(&self, client: &mut xds::XdsClient) -> Result<()> {
        client
            .report_heartbeat(
                &self.node_id,
                &self.interface,
                &self.interface_ips,
                self.applied_version.max(0),
                "ok",
                None,
            )
            .await
    }

    pub(super) async fn report_error_heartbeat(&self, client: &mut xds::XdsClient, details: &str) {
        let _ = client
            .report_heartbeat(
                &self.node_id,
                &self.interface,
                &self.interface_ips,
                self.applied_version.max(0),
                "error",
                Some(details),
            )
            .await;
    }
}
