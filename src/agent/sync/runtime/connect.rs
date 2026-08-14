use super::{AgentRuntime, xds};
use anyhow::Result;
use tracing::error;

type PolicyStream = tonic::Streaming<xds::proto::PolicyUpdate>;

impl AgentRuntime {
    pub(super) async fn connect_and_subscribe(
        &mut self,
    ) -> Result<Option<(xds::XdsClient, PolicyStream)>> {
        let Some(mut client) = self.connect_xds_client().await? else {
            return Ok(None);
        };
        if !self.report_starting_heartbeat(&mut client).await? {
            return Ok(None);
        }
        self.subscribe_policy_stream(client).await
    }

    async fn connect_xds_client(&mut self) -> Result<Option<xds::XdsClient>> {
        match xds::XdsClient::connect(xds::XdsClientConfig {
            control_url: self.args.control_url.clone(),
            agent_token: self.args.agent_token.clone(),
        })
        .await
        {
            Ok(client) => Ok(Some(client)),
            Err(err) => {
                let details = format!("{err:#}");
                error!(error = %details, "failed to connect xDS control plane");
                self.handle_control_plane_failure_and_wait(&details).await?;
                Ok(None)
            }
        }
    }

    async fn report_starting_heartbeat(&mut self, client: &mut xds::XdsClient) -> Result<bool> {
        if let Err(err) = client
            .report_heartbeat(
                &self.node_id,
                &self.interface,
                &self.interface_ips,
                0,
                "starting",
                None,
            )
            .await
        {
            let details = format!("{err:#}");
            error!(error = %details, "failed to report starting heartbeat");
            self.handle_control_plane_failure_and_wait(&details).await?;
            return Ok(false);
        }
        Ok(true)
    }

    async fn subscribe_policy_stream(
        &mut self,
        mut client: xds::XdsClient,
    ) -> Result<Option<(xds::XdsClient, PolicyStream)>> {
        match client
            .stream_policy(&self.node_id, &self.interface, self.applied_version)
            .await
        {
            Ok(stream) => Ok(Some((client, stream))),
            Err(err) => {
                let details = format!("{err:#}");
                error!(error = %details, "failed to subscribe to xDS policy stream");
                self.report_error_heartbeat(&mut client, &details).await;
                self.handle_control_plane_failure_and_wait(&details).await?;
                Ok(None)
            }
        }
    }
}
