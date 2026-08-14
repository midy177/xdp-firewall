use super::{KubernetesDiscovery, KubernetesWatchOutcome};
use anyhow::{Context, Result, bail};
use k8s_openapi::{
    ListableResource,
    api::{
        core::v1::{Node, Service},
        networking::v1::ServiceCIDR,
    },
};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use std::time::Duration;
use tracing::debug;

mod stream;

use stream::stream_watch_response;
#[cfg(test)]
pub(super) use stream::watch_line_changed;

impl KubernetesDiscovery {
    pub async fn watch_until_change(
        &self,
        path: &str,
        label: &str,
        timeout: Duration,
    ) -> Result<KubernetesWatchOutcome> {
        match label {
            "nodes" => {
                self.watch_until_typed_change::<Node>(path, label, timeout)
                    .await
            }
            "services" => {
                self.watch_until_typed_change::<Service>(path, label, timeout)
                    .await
            }
            "servicecidrs" => {
                self.watch_until_typed_change::<ServiceCIDR>(path, label, timeout)
                    .await
            }
            _ => bail!("unsupported Kubernetes watch target '{label}'"),
        }
    }

    async fn watch_until_typed_change<T>(
        &self,
        path: &str,
        label: &str,
        timeout: Duration,
    ) -> Result<KubernetesWatchOutcome>
    where
        T: DeserializeOwned + ListableResource,
    {
        let Some(resource_version) = self.list_resource_version::<T>(path, label).await? else {
            return Ok(KubernetesWatchOutcome::Unsupported);
        };
        let response = self
            .open_watch_response(path, label, timeout, &resource_version)
            .await?;
        if matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
        ) {
            debug!(
                status = %response.status(),
                label,
                "Kubernetes watch endpoint is unavailable"
            );
            return Ok(KubernetesWatchOutcome::Unsupported);
        }
        let response = response
            .error_for_status()
            .with_context(|| format!("Kubernetes watch '{label}' returned an error"))?;
        stream_watch_response::<T>(response, label).await
    }

    async fn open_watch_response(
        &self,
        path: &str,
        label: &str,
        timeout: Duration,
        resource_version: &str,
    ) -> Result<reqwest::Response> {
        let separator = if path.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{}{}watch=true&allowWatchBookmarks=true&timeoutSeconds={}&resourceVersion={}",
            self.api_server,
            path,
            separator,
            timeout.as_secs().max(1),
            resource_version
        );
        self.client
            .get(&url)
            .bearer_auth(&self.token)
            .timeout(timeout + Duration::from_secs(10))
            .send()
            .await
            .with_context(|| format!("failed to open Kubernetes watch '{label}'"))
    }
}
