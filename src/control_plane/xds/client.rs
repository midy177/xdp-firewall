use super::{
    XDS_MAX_MESSAGE_SIZE, proto::HeartbeatRequest, proto::firewall_xds_client::FirewallXdsClient,
};
use crate::cli::XdsTlsClientArgs;
use anyhow::{Context, Result, bail};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
use tracing::info;

mod drop_events;
mod geo_prefixes;
mod policy;

pub use policy::PolicyUpdateError;

#[derive(Debug, Clone, Default)]
pub struct XdsClientTls {
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

impl From<&XdsTlsClientArgs> for XdsClientTls {
    fn from(args: &XdsTlsClientArgs) -> Self {
        Self {
            ca_cert: args.xds_ca_cert.clone(),
            client_cert: args.xds_client_cert.clone(),
            client_key: args.xds_client_key.clone(),
        }
    }
}

#[derive(Clone)]
pub struct XdsClientConfig {
    pub control_url: String,
    pub agent_token: Option<String>,
    pub tls: XdsClientTls,
}

#[derive(Clone)]
pub struct XdsClient {
    inner: FirewallXdsClient<Channel>,
    agent_token: Option<String>,
}

#[derive(Debug)]
enum TlsDecision {
    Plain,
    Tls { client_identity: bool },
}

fn decide_tls(url: &str, tls: &XdsClientTls) -> Result<TlsDecision> {
    if url.starts_with("https://") {
        match (&tls.client_cert, &tls.client_key) {
            (None, None) => Ok(TlsDecision::Tls {
                client_identity: false,
            }),
            (Some(_), Some(_)) => Ok(TlsDecision::Tls {
                client_identity: true,
            }),
            (Some(_), None) => bail!(
                "--xds-client-cert is set without --xds-client-key; configure both or neither for https:// control URLs"
            ),
            (None, Some(_)) => bail!(
                "--xds-client-key is set without --xds-client-cert; configure both or neither for https:// control URLs"
            ),
        }
    } else if url.starts_with("http://") {
        if tls.ca_cert.is_some() || tls.client_cert.is_some() || tls.client_key.is_some() {
            bail!(
                "xDS control URL is http:// but TLS options (--xds-ca-cert/--xds-client-cert/--xds-client-key) are configured; use an https:// control URL or remove the TLS options"
            );
        }
        Ok(TlsDecision::Plain)
    } else {
        bail!("xDS control plane URL must start with http:// or https://, got '{url}'")
    }
}

fn build_endpoint(config: &XdsClientConfig) -> Result<Endpoint> {
    let url = config.control_url.trim();
    let endpoint = Endpoint::from_shared(url.to_string())
        .with_context(|| format!("invalid xDS control plane URL '{url}'"))?;
    match decide_tls(url, &config.tls)? {
        TlsDecision::Plain => Ok(endpoint),
        TlsDecision::Tls { client_identity } => {
            let tls = build_client_tls_config(&config.tls, client_identity)?;
            endpoint
                .tls_config(tls)
                .with_context(|| format!("failed to configure TLS for xDS control plane '{url}'"))
        }
    }
}

fn build_client_tls_config(tls: &XdsClientTls, client_identity: bool) -> Result<ClientTlsConfig> {
    let mut config = ClientTlsConfig::new();
    if let Some(ca) = &tls.ca_cert {
        config = config.ca_certificate(Certificate::from_pem(read_pem(ca)?));
    } else {
        info!(
            "xDS control URL uses https:// without --xds-ca-cert; trusting system root certificates"
        );
        config = config.with_native_roots();
    }
    if client_identity {
        let cert = tls
            .client_cert
            .as_ref()
            .expect("client identity pairing validated by decide_tls");
        let key = tls
            .client_key
            .as_ref()
            .expect("client identity pairing validated by decide_tls");
        config = config.identity(Identity::from_pem(read_pem(cert)?, read_pem(key)?));
    }
    Ok(config)
}

fn read_pem(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .with_context(|| format!("failed to read xDS TLS PEM file {}", path.display()))
}

impl XdsClient {
    pub async fn connect(config: XdsClientConfig) -> Result<Self> {
        let channel = build_endpoint(&config)?.connect().await.with_context(|| {
            format!("failed to connect xDS control plane {}", config.control_url)
        })?;
        let inner = FirewallXdsClient::new(channel)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(ca: Option<&str>, cert: Option<&str>, key: Option<&str>) -> XdsClientTls {
        XdsClientTls {
            ca_cert: ca.map(PathBuf::from),
            client_cert: cert.map(PathBuf::from),
            client_key: key.map(PathBuf::from),
        }
    }

    #[test]
    fn http_without_tls_material_stays_plain() {
        assert!(matches!(
            decide_tls("http://127.0.0.1:50051", &tls(None, None, None)).unwrap(),
            TlsDecision::Plain
        ));
    }

    #[test]
    fn https_enables_tls_with_optional_client_identity() {
        assert!(matches!(
            decide_tls("https://127.0.0.1:50051", &tls(None, None, None)).unwrap(),
            TlsDecision::Tls {
                client_identity: false
            }
        ));
        assert!(matches!(
            decide_tls(
                "https://control.example:50051",
                &tls(Some("ca.pem"), Some("client.pem"), Some("client.key"))
            )
            .unwrap(),
            TlsDecision::Tls {
                client_identity: true
            }
        ));
    }

    #[test]
    fn http_with_tls_material_is_rejected() {
        let err = decide_tls("http://127.0.0.1:50051", &tls(Some("ca.pem"), None, None))
            .expect_err("http URL with TLS material must fail");
        assert!(format!("{err:#}").contains("https://"));
    }

    #[test]
    fn missing_scheme_is_rejected() {
        let err = decide_tls("127.0.0.1:50051", &tls(None, None, None))
            .expect_err("scheme-less URL must fail");
        assert!(format!("{err:#}").contains("http:// or https://"));
    }

    #[test]
    fn unpaired_client_identity_is_rejected() {
        let err = decide_tls(
            "https://control.example:50051",
            &tls(None, Some("client.pem"), None),
        )
        .expect_err("client cert without key must fail");
        assert!(format!("{err:#}").contains("--xds-client-cert"));
        let err = decide_tls(
            "https://control.example:50051",
            &tls(None, None, Some("client.key")),
        )
        .expect_err("client key without cert must fail");
        assert!(format!("{err:#}").contains("--xds-client-key"));
    }
}
