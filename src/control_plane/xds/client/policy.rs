use super::super::proto::{FetchPolicyRequest, PolicyUpdate, StreamPolicyRequest};
use super::XdsClient;
use crate::policy::model::PolicySnapshot;
use anyhow::{Context, Result};
use std::fmt;
use tonic::{Status, Streaming};

#[derive(Debug)]
pub enum PolicyUpdateError {
    InvalidPolicyJson(anyhow::Error),
    ExternalGeoPrefixes(anyhow::Error),
}

impl PolicyUpdateError {
    #[must_use]
    pub fn is_control_plane_failure(&self) -> bool {
        match self {
            Self::InvalidPolicyJson(_) => false,
            Self::ExternalGeoPrefixes(err) => err.downcast_ref::<Status>().is_some(),
        }
    }
}

impl fmt::Display for PolicyUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicyJson(err) | Self::ExternalGeoPrefixes(err) => {
                write!(formatter, "{err:#}")
            }
        }
    }
}

impl std::error::Error for PolicyUpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicyJson(err) | Self::ExternalGeoPrefixes(err) => err.source(),
        }
    }
}

impl XdsClient {
    pub async fn fetch_policy(
        &mut self,
        node_id: &str,
        interface_name: &str,
        current_version: i64,
    ) -> Result<Option<(i64, PolicySnapshot)>> {
        let request = self.with_auth(FetchPolicyRequest {
            node_id: node_id.to_string(),
            interface_name: interface_name.to_string(),
            current_version,
            supports_external_geo_prefixes: true,
        })?;
        let response = self.inner.fetch_policy(request).await?.into_inner();
        if response.unchanged {
            return Ok(None);
        }
        let mut snapshot: PolicySnapshot = serde_json::from_str(&response.policy_json)
            .context("xDS control plane returned invalid policy JSON")?;
        if response.external_geo_prefixes {
            snapshot.geo_prefixes = self.fetch_geo_prefixes(response.geo_prefix_version).await?;
        }
        Ok(Some((response.version, snapshot)))
    }

    pub async fn stream_policy(
        &mut self,
        node_id: &str,
        interface_name: &str,
        current_version: i64,
    ) -> Result<Streaming<PolicyUpdate>> {
        let request = self.with_auth(StreamPolicyRequest {
            node_id: node_id.to_string(),
            interface_name: interface_name.to_string(),
            current_version,
            supports_external_geo_prefixes: true,
        })?;
        Ok(self.inner.stream_policy(request).await?.into_inner())
    }

    pub async fn policy_from_update(
        &mut self,
        update: PolicyUpdate,
    ) -> std::result::Result<(i64, Option<PolicySnapshot>, bool), PolicyUpdateError> {
        let mut snapshot = policy_snapshot_from_update(&update)?;
        if let Some(snapshot) = snapshot.as_mut()
            && update.external_geo_prefixes
        {
            snapshot.geo_prefixes = self
                .fetch_geo_prefixes(update.geo_prefix_version)
                .await
                .map_err(PolicyUpdateError::ExternalGeoPrefixes)?;
        }
        Ok((update.version, snapshot, update.drop_monitor_enabled))
    }
}

fn policy_snapshot_from_update(
    update: &PolicyUpdate,
) -> std::result::Result<Option<PolicySnapshot>, PolicyUpdateError> {
    if update.policy_json.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<PolicySnapshot>(&update.policy_json)
        .context("xDS control plane returned invalid policy JSON")
        .map(Some)
        .map_err(PolicyUpdateError::InvalidPolicyJson)
}
