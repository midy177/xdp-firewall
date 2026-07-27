use crate::cli::K8sDiscoveryArgs;
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use ipnet::IpNet;
use k8s_openapi::{
    List, ListableResource,
    api::{
        core::v1::{Node, Service},
        networking::v1::ServiceCIDR,
    },
    apimachinery::pkg::apis::meta::v1::WatchEvent,
};
use reqwest::{Certificate, StatusCode};
use serde::de::DeserializeOwned;
use std::{collections::HashSet, net::IpAddr, path::Path, time::Duration};
use tracing::{debug, info, trace, warn};

#[derive(Debug, Clone)]
pub struct KubernetesDiscovery {
    client: reqwest::Client,
    api_server: String,
    token: String,
}

#[derive(Debug, Clone, Default)]
pub struct KubernetesRuntimeCidrs {
    pub cidrs: Vec<IpNet>,
    pub node_ips: usize,
    pub pod_cidrs: usize,
    pub service_cidrs: usize,
    pub service_cidr_partial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KubernetesWatchOutcome {
    Changed,
    Ended,
    Unsupported,
}

impl KubernetesDiscovery {
    pub fn from_args(args: &K8sDiscoveryArgs) -> Result<Option<Self>> {
        if !args.k8s_discovery {
            return Ok(None);
        }
        let api_server = args
            .k8s_api_server
            .clone()
            .or_else(default_api_server)
            .context(
                "Kubernetes discovery is enabled but Kubernetes API server is not configured",
            )?;
        let token = std::fs::read_to_string(&args.k8s_token_path)
            .with_context(|| format!("failed to read Kubernetes token '{}'", args.k8s_token_path))?
            .trim()
            .to_string();
        if token.is_empty() {
            bail!("Kubernetes service account token is empty");
        }
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(5));
        if Path::new(&args.k8s_ca_cert_path).exists() {
            let ca = std::fs::read(&args.k8s_ca_cert_path).with_context(|| {
                format!(
                    "failed to read Kubernetes CA certificate '{}'",
                    args.k8s_ca_cert_path
                )
            })?;
            builder = builder.add_root_certificate(
                Certificate::from_pem(&ca).context("Kubernetes CA certificate is not valid PEM")?,
            );
        } else {
            warn!(
                path = %args.k8s_ca_cert_path,
                "Kubernetes CA certificate was not found; using default TLS roots"
            );
        }
        let client = builder
            .build()
            .context("failed to build Kubernetes discovery HTTP client")?;
        info!(api_server, "enabled Kubernetes runtime address discovery");
        Ok(Some(Self {
            client,
            api_server: api_server.trim_end_matches('/').to_string(),
            token,
        }))
    }

    pub async fn discover(&self) -> Result<KubernetesRuntimeCidrs> {
        let mut cidrs = Vec::new();
        let mut seen = HashSet::new();
        let nodes = self.get_list::<Node>("/api/v1/nodes", "nodes").await?;
        let mut node_ips = 0;
        let mut pod_cidrs = 0;
        for node in &nodes.items {
            if let Some(status) = &node.status
                && let Some(addresses) = &status.addresses
            {
                for address in addresses {
                    if matches!(address.type_.as_str(), "InternalIP" | "ExternalIP")
                        && let Some(cidr) = ip_to_host_cidr(&address.address)?
                        && insert_unique(&mut cidrs, &mut seen, cidr)
                    {
                        node_ips += 1;
                    }
                }
            }
            if let Some(spec) = &node.spec {
                let mut node_has_pod_cidr = false;
                for value in spec.pod_cidrs.as_deref().unwrap_or_default() {
                    let cidr = value
                        .parse::<IpNet>()
                        .with_context(|| format!("invalid Kubernetes podCIDR '{value}'"))?;
                    node_has_pod_cidr = true;
                    if insert_unique(&mut cidrs, &mut seen, cidr) {
                        pod_cidrs += 1;
                    }
                }
                if !node_has_pod_cidr && let Some(value) = spec.pod_cidr.as_deref() {
                    let cidr = value
                        .parse::<IpNet>()
                        .with_context(|| format!("invalid Kubernetes podCIDR '{value}'"))?;
                    if insert_unique(&mut cidrs, &mut seen, cidr) {
                        pod_cidrs += 1;
                    }
                }
            }
        }

        let (service_cidrs, service_cidr_partial) = match self
            .get_list_optional::<ServiceCIDR>(
                "/apis/networking.k8s.io/v1/servicecidrs",
                "servicecidrs",
            )
            .await
        {
            Ok(Some(servicecidrs)) => {
                let count = add_service_cidrs(&mut cidrs, &mut seen, &servicecidrs.items)?;
                (count, false)
            }
            Ok(None) => {
                let services = self
                    .get_list::<Service>("/api/v1/services", "services")
                    .await?;
                let count = add_service_cluster_ips(&mut cidrs, &mut seen, &services.items)?;
                (count, true)
            }
            Err(err) if is_forbidden_error(&err) => {
                warn!(
                    error = %err,
                    "Kubernetes ServiceCIDR API is forbidden; falling back to existing Service ClusterIPs"
                );
                let services = self
                    .get_list::<Service>("/api/v1/services", "services")
                    .await?;
                let count = add_service_cluster_ips(&mut cidrs, &mut seen, &services.items)?;
                (count, true)
            }
            Err(err) => return Err(err),
        };

        trace!(
            node_ips,
            pod_cidrs,
            service_cidrs,
            service_cidr_partial,
            total = cidrs.len(),
            "discovered Kubernetes runtime trusted CIDRs"
        );
        Ok(KubernetesRuntimeCidrs {
            cidrs,
            node_ips,
            pod_cidrs,
            service_cidrs,
            service_cidr_partial,
        })
    }

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
        let separator = if path.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{}{}watch=true&allowWatchBookmarks=true&timeoutSeconds={}&resourceVersion={}",
            self.api_server,
            path,
            separator,
            timeout.as_secs().max(1),
            resource_version
        );
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .timeout(timeout + Duration::from_secs(10))
            .send()
            .await
            .with_context(|| format!("failed to open Kubernetes watch '{label}'"))?;
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
        let mut stream = response.bytes_stream();
        let mut pending = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.with_context(|| format!("failed to read Kubernetes watch '{label}'"))?;
            pending.extend_from_slice(&chunk);
            while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                let line = pending.drain(..=newline).collect::<Vec<_>>();
                let line = String::from_utf8_lossy(&line);
                if watch_line_changed::<T>(line.trim(), label)? {
                    return Ok(KubernetesWatchOutcome::Changed);
                }
            }
        }
        if !pending.is_empty() {
            let line = String::from_utf8_lossy(&pending);
            if watch_line_changed::<T>(line.trim(), label)? {
                return Ok(KubernetesWatchOutcome::Changed);
            }
        }
        Ok(KubernetesWatchOutcome::Ended)
    }

    async fn get_list<T>(&self, path: &str, label: &str) -> Result<List<T>>
    where
        T: DeserializeOwned + ListableResource,
    {
        self.get_list_optional(path, label)
            .await?
            .with_context(|| format!("Kubernetes API path '{path}' was not found"))
    }

    async fn get_list_optional<T>(&self, path: &str, label: &str) -> Result<Option<List<T>>>
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

    async fn list_resource_version<T>(&self, path: &str, label: &str) -> Result<Option<String>>
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
        Ok(Some(resource_version.to_string()))
    }
}

fn watch_line_changed<T>(line: &str, label: &str) -> Result<bool>
where
    T: DeserializeOwned,
{
    if line.is_empty() {
        return Ok(false);
    }
    let event = serde_json::from_str::<WatchEvent<T>>(line)
        .with_context(|| format!("Kubernetes watch '{label}' returned invalid event JSON"))?;
    match event {
        WatchEvent::Added(_) | WatchEvent::Modified(_) | WatchEvent::Deleted(_) => Ok(true),
        WatchEvent::Bookmark { .. } => Ok(false),
        WatchEvent::ErrorStatus(status) => {
            let message = status
                .message
                .as_deref()
                .unwrap_or("Kubernetes watch error");
            bail!("Kubernetes watch '{label}' returned ERROR event: {message}")
        }
        WatchEvent::ErrorOther(error) => {
            bail!("Kubernetes watch '{label}' returned non-Status ERROR event: {error:?}")
        }
    }
}

fn is_forbidden_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("returned forbidden"))
}

fn default_api_server() -> Option<String> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
        .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
        .unwrap_or_else(|_| "443".to_string());
    Some(format!("https://{host}:{port}"))
}

fn add_service_cidrs(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    servicecidrs: &[ServiceCIDR],
) -> Result<usize> {
    let mut count = 0;
    for servicecidr in servicecidrs {
        if let Some(spec) = &servicecidr.spec
            && let Some(values) = &spec.cidrs
        {
            for value in values {
                let cidr = value
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid Kubernetes ServiceCIDR '{value}'"))?;
                if insert_unique(cidrs, seen, cidr) {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

fn add_service_cluster_ips(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    services: &[Service],
) -> Result<usize> {
    let mut count = 0;
    for service in services {
        if let Some(spec) = &service.spec {
            if let Some(values) = &spec.cluster_ips {
                for value in values {
                    if let Some(cidr) = ip_to_host_cidr(value)?
                        && insert_unique(cidrs, seen, cidr)
                    {
                        count += 1;
                    }
                }
            }
            if let Some(value) = &spec.cluster_ip
                && let Some(cidr) = ip_to_host_cidr(value)?
                && insert_unique(cidrs, seen, cidr)
            {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn ip_to_host_cidr(value: &str) -> Result<Option<IpNet>> {
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let ip = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid Kubernetes IP '{value}'"))?;
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Ok(Some(IpNet::new(ip, prefix)?))
}

fn insert_unique(cidrs: &mut Vec<IpNet>, seen: &mut HashSet<IpNet>, cidr: IpNet) -> bool {
    if seen.insert(cidr) {
        cidrs.push(cidr);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_headless_service_cluster_ip() {
        assert!(ip_to_host_cidr("None").unwrap().is_none());
    }

    #[test]
    fn converts_node_ip_to_host_cidr() {
        assert_eq!(
            ip_to_host_cidr("10.0.0.5").unwrap().unwrap().to_string(),
            "10.0.0.5/32"
        );
    }

    #[test]
    fn watch_bookmark_is_not_a_change() {
        assert!(
            !watch_line_changed::<Node>(
                r#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"1"}}}"#,
                "nodes"
            )
            .unwrap()
        );
    }

    #[test]
    fn watch_added_is_a_change_after_resource_version_anchor() {
        assert!(watch_line_changed::<Node>(r#"{"type":"ADDED","object":{}}"#, "nodes").unwrap());
    }

    #[test]
    fn watch_error_is_not_reported_as_policy_change() {
        let err = watch_line_changed::<Node>(
            r#"{"type":"ERROR","object":{"message":"too old resource version"}}"#,
            "nodes",
        )
        .unwrap_err();
        assert!(err.to_string().contains("too old resource version"));
    }
}
