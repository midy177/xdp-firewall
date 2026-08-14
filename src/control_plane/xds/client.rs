use super::{
    XDS_MAX_MESSAGE_SIZE, proto::HeartbeatRequest, proto::firewall_xds_client::FirewallXdsClient,
};
use anyhow::{Context, Result};
use std::net::IpAddr;
use tonic::Request;
use tonic::transport::Channel;

mod drop_events;
mod geo_prefixes;
mod policy;

pub use policy::PolicyUpdateError;

#[derive(Clone)]
pub struct XdsClientConfig {
    pub control_url: String,
    pub agent_token: Option<String>,
}

#[derive(Clone)]
pub struct XdsClient {
    inner: FirewallXdsClient<Channel>,
    agent_token: Option<String>,
}

impl XdsClient {
    pub async fn connect(config: XdsClientConfig) -> Result<Self> {
        let inner = FirewallXdsClient::connect(config.control_url.clone())
            .await
            .with_context(|| format!("failed to connect xDS control plane {}", config.control_url))?
            .max_decoding_message_size(XDS_MAX_MESSAGE_SIZE)
            .max_encoding_message_size(XDS_MAX_MESSAGE_SIZE);
        Ok(Self {
            inner,
            agent_token: config.agent_token.filter(|token| !token.trim().is_empty()),
        })
    }

    pub async fn report_heartbeat(
        &mut self,
        node_id: &str,
        interface_name: &str,
        interface_ips: &[IpAddr],
        last_applied_version: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let request = self.with_auth(HeartbeatRequest {
            node_id: node_id.to_string(),
            interface_name: interface_name.to_string(),
            interface_ips: interface_ips.iter().map(ToString::to_string).collect(),
            last_applied_version,
            status: status.to_string(),
            error: error.unwrap_or_default().to_string(),
        })?;
        self.inner.report_heartbeat(request).await?;
        Ok(())
    }

    fn with_auth<T>(&self, message: T) -> Result<Request<T>> {
        let mut request = Request::new(message);
        if let Some(token) = self.agent_token.as_deref() {
            let bearer = format!("Bearer {token}");
            request.metadata_mut().insert(
                "authorization",
                bearer
                    .parse()
                    .context("failed to build xDS authorization metadata")?,
            );
            request.metadata_mut().insert(
                "x-agent-token",
                token
                    .parse()
                    .context("failed to build xDS token metadata")?,
            );
        }
        Ok(request)
    }
}
