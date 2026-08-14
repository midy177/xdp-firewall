use super::{AgentRuntime, AgentStreamOutcome, StreamMessageOutcome, drop_monitor, xds};
use crate::agent::policy_apply;
use anyhow::Result;
use tokio::time::interval;
use tracing::{error, info};

impl AgentRuntime {
    pub(super) async fn run_policy_stream(
        &mut self,
        client: &mut xds::XdsClient,
        stream: &mut tonic::Streaming<xds::proto::PolicyUpdate>,
    ) -> Result<AgentStreamOutcome> {
        let mut heartbeat_tick = interval(self.heartbeat_interval);
        heartbeat_tick.tick().await;
        loop {
            tokio::select! {
                update = stream.message() => {
                    match self.handle_stream_message(client, update).await? {
                        StreamMessageOutcome::Continue => {}
                        StreamMessageOutcome::Reconnect => return Ok(AgentStreamOutcome::Reconnect),
                    }
                }
                _ = heartbeat_tick.tick() => {
                    drop_monitor::log_xdp_stats(&self.xdp);
                    if let Err(err) = self.report_ok_heartbeat(client).await {
                        let details = format!("{err:#}");
                        error!(error = %details, "failed to report heartbeat; reconnecting");
                        self.handle_control_plane_failure_and_wait(&details).await?;
                        return Ok(AgentStreamOutcome::Reconnect);
                    }
                    self.offline.record_control_plane_healthy();
                }
                result = tokio::signal::ctrl_c() => {
                    result?;
                    client.report_heartbeat(&self.node_id, &self.interface, &self.interface_ips, self.applied_version.max(0), "stopped", None).await?;
                    return Ok(AgentStreamOutcome::Shutdown);
                }
            }
        }
    }

    async fn handle_stream_message(
        &mut self,
        client: &mut xds::XdsClient,
        update: Result<Option<xds::proto::PolicyUpdate>, tonic::Status>,
    ) -> Result<StreamMessageOutcome> {
        match update {
            Ok(Some(update)) => self.process_policy_update(client, update).await,
            Ok(None) => {
                info!("xDS policy stream closed; reconnecting");
                self.handle_control_plane_failure_and_wait("xDS policy stream closed")
                    .await?;
                Ok(StreamMessageOutcome::Reconnect)
            }
            Err(err) => {
                let details = format!("{err:#}");
                error!(error = %details, "xDS policy stream failed; reconnecting");
                self.report_error_heartbeat(client, &details).await;
                self.handle_control_plane_failure_and_wait(&details).await?;
                Ok(StreamMessageOutcome::Reconnect)
            }
        }
    }

    async fn process_policy_update(
        &mut self,
        client: &mut xds::XdsClient,
        update: xds::proto::PolicyUpdate,
    ) -> Result<StreamMessageOutcome> {
        let (version, snapshot, drop_monitor_enabled) =
            match client.policy_from_update(update).await {
                Ok(update) => update,
                Err(err) => {
                    let details = format!("{err:#}");
                    error!(error = %details, "failed to decode xDS policy update");
                    self.report_error_heartbeat(client, &details).await;
                    if err.is_control_plane_failure() {
                        self.handle_control_plane_failure_and_wait(&details).await?;
                    } else {
                        tokio::time::sleep(self.reconnect_delay).await;
                    }
                    return Ok(StreamMessageOutcome::Reconnect);
                }
            };
        drop_monitor::reconcile(
            &mut self.xdp,
            &mut self.drop_monitor,
            drop_monitor_enabled,
            &self.args,
            &self.node_id,
            &self.interface,
        );
        let Some(snapshot) = snapshot else {
            info!(
                enabled = drop_monitor_enabled,
                "applied xDS drop monitor setting"
            );
            return Ok(StreamMessageOutcome::Continue);
        };

        match policy_apply::apply_latest(&mut self.xdp, snapshot, &self.args.control_url, version) {
            Ok(applied) => {
                self.applied_version = applied;
                self.offline.record_policy_applied();
                drop_monitor::log_xdp_stats(&self.xdp);
                if let Err(err) = self.report_ok_heartbeat(client).await {
                    let details = format!("{err:#}");
                    error!(error = %details, "failed to report ok heartbeat after policy apply");
                    self.handle_control_plane_failure_and_wait(&details).await?;
                    return Ok(StreamMessageOutcome::Reconnect);
                }
                self.offline.record_control_plane_healthy();
            }
            Err(err) => {
                let details = format!("{err:#}");
                error!(error = %details, "failed to apply firewall policy");
                self.report_error_heartbeat(client, &details).await;
                tokio::time::sleep(self.reconnect_delay).await;
                return Ok(StreamMessageOutcome::Reconnect);
            }
        }
        Ok(StreamMessageOutcome::Continue)
    }
}
