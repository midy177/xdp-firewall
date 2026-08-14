use super::KubernetesDiscovery;
use anyhow::{Context, Result, bail};
use k8s_openapi::{List, ListableResource};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tracing::debug;

impl KubernetesDiscovery {
    pub(super) async fn get_list<T>(&self, path: &str, label: &str) -> Result<List<T>>
    where
        T: DeserializeOwned + ListableResource,
    {
        self.get_list_optional(path, label)
            .await?
            .with_context(|| format!("Kubernetes API path '{path}' was not found"))
    }

    pub(super) async fn get_list_optional<T>(
        &self,
        path: &str,
        label: &str,
    ) -> Result<Option<List<T>>>
    where
        T: DeserializeOwned + ListableResource,
    {
        let url = format!("{}{}", self.api_server, path);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("failed to call Kubernetes API '{path}'"))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() == StatusCode::FORBIDDEN {
            bail!("Kubernetes API '{path}' returned forbidden");
        }
        let response = response
            .error_for_status()
            .with_context(|| format!("Kubernetes API '{path}' returned an error"))?;
        Ok(Some(response.json::<List<T>>().await.with_context(
            || format!("Kubernetes API '{label}' returned invalid Kubernetes list JSON"),
        )?))
    }

    pub(super) async fn list_resource_version<T>(
        &self,
        path: &str,
        label: &str,
    ) -> Result<Option<String>>
    where
        T: DeserializeOwned + ListableResource,
    {
        let Some(list) = self.get_list_optional::<T>(path, label).await? else {
            debug!(label, "Kubernetes watch base list is unavailable");
            return Ok(None);
        };
        let Some(resource_version) = list.metadata.resource_version else {
            debug!(
                label,
                "Kubernetes watch base list did not include metadata.resourceVersion"
            );
            return Ok(None);
        };
        Ok(Some(resource_version.clone()))
    }
}

pub(super) fn is_forbidden_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("returned forbidden"))
}
