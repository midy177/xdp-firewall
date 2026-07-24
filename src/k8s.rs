use crate::cli::K8sDiscoveryArgs;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use reqwest::{Certificate, StatusCode};
use serde_json::Value;
use std::{collections::HashSet, net::IpAddr, path::Path, time::Duration};
use tracing::{info, warn};

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
        let nodes = self.get_json("/api/v1/nodes").await?;
        let mut node_ips = 0;
        let mut pod_cidrs = 0;
        for node in items(&nodes) {
            for address in array_at(node, &["status", "addresses"]) {
                if string_at(address, &["type"])
                    .is_some_and(|kind| matches!(kind, "InternalIP" | "ExternalIP"))
                    && let Some(value) = string_at(address, &["address"])
                    && let Some(cidr) = ip_to_host_cidr(value)?
                    && insert_unique(&mut cidrs, &mut seen, cidr)
                {
                    node_ips += 1;
                }
            }
            let mut node_has_pod_cidr = false;
            for value in strings_at(node, &["spec", "podCIDRs"]) {
                let cidr = value
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid Kubernetes podCIDR '{value}'"))?;
                node_has_pod_cidr = true;
                if insert_unique(&mut cidrs, &mut seen, cidr) {
                    pod_cidrs += 1;
                }
            }
            if !node_has_pod_cidr && let Some(value) = string_at(node, &["spec", "podCIDR"]) {
                let cidr = value
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid Kubernetes podCIDR '{value}'"))?;
                if insert_unique(&mut cidrs, &mut seen, cidr) {
                    pod_cidrs += 1;
                }
            }
        }

        let (service_cidrs, service_cidr_partial) = match self
            .get_json_optional("/apis/networking.k8s.io/v1/servicecidrs")
            .await
        {
            Ok(Some(servicecidrs)) => {
                let count = add_service_cidrs(&mut cidrs, &mut seen, &servicecidrs)?;
                (count, false)
            }
            Ok(None) => {
                let services = self.get_json("/api/v1/services").await?;
                let count = add_service_cluster_ips(&mut cidrs, &mut seen, &services)?;
                (count, true)
            }
            Err(err) if is_forbidden_error(&err) => {
                warn!(
                    error = %err,
                    "Kubernetes ServiceCIDR API is forbidden; falling back to existing Service ClusterIPs"
                );
                let services = self.get_json("/api/v1/services").await?;
                let count = add_service_cluster_ips(&mut cidrs, &mut seen, &services)?;
                (count, true)
            }
            Err(err) => return Err(err),
        };

        info!(
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

    async fn get_json(&self, path: &str) -> Result<Value> {
        self.get_json_optional(path)
            .await?
            .with_context(|| format!("Kubernetes API path '{path}' was not found"))
    }

    async fn get_json_optional(&self, path: &str) -> Result<Option<Value>> {
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
        Ok(Some(response.json().await.with_context(|| {
            format!("Kubernetes API '{path}' returned invalid JSON")
        })?))
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
    servicecidrs: &Value,
) -> Result<usize> {
    let mut count = 0;
    for item in items(servicecidrs) {
        for value in strings_at(item, &["spec", "cidrs"]) {
            let cidr = value
                .parse::<IpNet>()
                .with_context(|| format!("invalid Kubernetes ServiceCIDR '{value}'"))?;
            if insert_unique(cidrs, seen, cidr) {
                count += 1;
            }
        }
        if let Some(value) = string_at(item, &["spec", "cidr"]) {
            let cidr = value
                .parse::<IpNet>()
                .with_context(|| format!("invalid Kubernetes ServiceCIDR '{value}'"))?;
            if insert_unique(cidrs, seen, cidr) {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn add_service_cluster_ips(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    services: &Value,
) -> Result<usize> {
    let mut count = 0;
    for service in items(services) {
        for value in strings_at(service, &["spec", "clusterIPs"]) {
            if let Some(cidr) = ip_to_host_cidr(value)?
                && insert_unique(cidrs, seen, cidr)
            {
                count += 1;
            }
        }
        if let Some(value) = string_at(service, &["spec", "clusterIP"])
            && let Some(cidr) = ip_to_host_cidr(value)?
            && insert_unique(cidrs, seen, cidr)
        {
            count += 1;
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

fn items(value: &Value) -> impl Iterator<Item = &Value> {
    value
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> impl Iterator<Item = &'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn strings_at<'a>(value: &'a Value, path: &[&str]) -> impl Iterator<Item = &'a str> {
    array_at(value, path).filter_map(Value::as_str)
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
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
}
