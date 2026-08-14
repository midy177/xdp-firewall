use super::KubernetesDiscovery;
use crate::cli::K8sDiscoveryArgs;
use anyhow::{Context, Result, bail};
use reqwest::Certificate;
use std::{path::Path, time::Duration};
use tracing::{info, warn};

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
        let token = service_account_token(&args.k8s_token_path)?;
        let client = discovery_http_client(&args.k8s_ca_cert_path)?;
        info!(api_server, "enabled Kubernetes runtime address discovery");
        Ok(Some(Self {
            client,
            api_server: api_server.trim_end_matches('/').to_string(),
            token,
        }))
    }
}

fn service_account_token(path: &str) -> Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read Kubernetes token '{path}'"))?
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("Kubernetes service account token is empty");
    }
    Ok(token)
}

fn discovery_http_client(ca_cert_path: &str) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(5));
    if Path::new(ca_cert_path).exists() {
        let ca = std::fs::read(ca_cert_path).with_context(|| {
            format!("failed to read Kubernetes CA certificate '{ca_cert_path}'")
        })?;
        builder = builder.add_root_certificate(
            Certificate::from_pem(&ca).context("Kubernetes CA certificate is not valid PEM")?,
        );
    } else {
        warn!(
            path = %ca_cert_path,
            "Kubernetes CA certificate was not found; using default TLS roots"
        );
    }
    builder
        .build()
        .context("failed to build Kubernetes discovery HTTP client")
}

fn default_api_server() -> Option<String> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
        .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
        .unwrap_or_else(|_| "443".to_string());
    Some(format!("https://{host}:{port}"))
}
