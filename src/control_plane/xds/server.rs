use super::{
    AUTO_REFRESH_INTERVAL, DropEventHub, K8S_WATCH_TIMEOUT, TEMP_BAN_CLEANUP_INTERVAL,
    THREAT_MISSING_PREFIX_POLL_INTERVAL, XDS_MAX_MESSAGE_SIZE, XdsService,
    auth::reject_unsafe_unauthenticated_bind,
    k8s,
    proto::firewall_xds_server::FirewallXdsServer,
    refresh::TempBanCleanup,
    runtime_cidrs::{RuntimeTrustedCidrs, normalize_runtime_trusted_cidrs},
};
use crate::{
    cli::{XdsArgs, XdsTlsServerArgs},
    intelligence::geo,
};
use anyhow::{Context, Result, bail};
use sea_orm::DatabaseConnection;
use std::{net::SocketAddr, path::Path, time::Duration};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

mod background;

use background::start_background_tasks;

pub async fn serve(
    db: DatabaseConnection,
    args: XdsArgs,
    drop_events: DropEventHub,
    geo_lookup: geo::GeoIpLookup,
) -> Result<()> {
    let bind = parse_bind(&args.bind)?;
    let push_interval = Duration::from_secs(args.push_interval_seconds.max(1));
    let runtime_trusted_cidrs = build_runtime_trusted_cidrs(&args).await?;
    let agent_token = args.agent_token.filter(|token| !token.trim().is_empty());
    reject_unsafe_unauthenticated_bind(bind, agent_token.as_deref())?;
    log_server_start(
        bind,
        &agent_token,
        push_interval,
        &runtime_trusted_cidrs,
        args.standby,
    );
    let threat_lookup = start_background_tasks(&db, &geo_lookup, args.standby);
    let tls = build_server_tls_config(&args.xds_tls)?;
    match &tls {
        None => info!("xDS gRPC TLS disabled (plaintext)"),
        Some((_, mutual_tls)) => info!(
            mutual_tls,
            "xDS gRPC TLS enabled; agents must connect with https:// control URLs"
        ),
    }
    let mut builder = Server::builder();
    if let Some((config, _)) = tls {
        builder = builder.tls_config(config)?;
    }
    builder
        .add_service(
            FirewallXdsServer::new(XdsService {
                db,
                agent_token,
                push_interval,
                drop_events,
                runtime_trusted_cidrs,
                temp_ban_cleanup: TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL, args.standby),
                geo_lookup,
                threat_lookup,
                standby: args.standby,
            })
            .max_decoding_message_size(XDS_MAX_MESSAGE_SIZE)
            .max_encoding_message_size(XDS_MAX_MESSAGE_SIZE),
        )
        .serve(bind)
        .await
        .context("xDS gRPC server failed")
}

fn build_server_tls_config(args: &XdsTlsServerArgs) -> Result<Option<(ServerTlsConfig, bool)>> {
    let cert = args.xds_tls_cert.as_ref();
    let key = args.xds_tls_key.as_ref();
    let client_ca = args.xds_tls_client_ca.as_ref();
    if cert.is_none() && key.is_none() && client_ca.is_none() {
        return Ok(None);
    }
    let (cert, key) = match (cert, key) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) => bail!(
            "--xds-tls-cert is set without --xds-tls-key; configure both to enable TLS or leave both unset"
        ),
        (None, Some(_)) => bail!(
            "--xds-tls-key is set without --xds-tls-cert; configure both to enable TLS or leave both unset"
        ),
        (None, None) => bail!(
            "--xds-tls-client-ca requires --xds-tls-cert and --xds-tls-key; configure server TLS before requiring client certificates"
        ),
    };
    let identity = Identity::from_pem(read_pem(cert)?, read_pem(key)?);
    let mut tls = ServerTlsConfig::new().identity(identity);
    let mutual_tls = match client_ca {
        Some(ca) => {
            tls = tls.client_ca_root(Certificate::from_pem(read_pem(ca)?));
            true
        }
        None => false,
    };
    Ok(Some((tls, mutual_tls)))
}

fn read_pem(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .with_context(|| format!("failed to read xDS TLS PEM file {}", path.display()))
}

fn parse_bind(bind: &str) -> Result<SocketAddr> {
    bind.parse()
        .with_context(|| format!("invalid xDS bind address '{bind}'"))
}

async fn build_runtime_trusted_cidrs(args: &XdsArgs) -> Result<RuntimeTrustedCidrs> {
    let configured_cidrs = normalize_runtime_trusted_cidrs(&args.trusted_cidrs)?;
    let k8s_discovery = k8s::KubernetesDiscovery::from_args(&args.k8s)?;
    let runtime_trusted_cidrs = RuntimeTrustedCidrs::new(configured_cidrs, k8s_discovery);
    runtime_trusted_cidrs.initial_refresh().await;
    runtime_trusted_cidrs.spawn_watch();
    Ok(runtime_trusted_cidrs)
}

fn log_server_start(
    bind: SocketAddr,
    agent_token: &Option<String>,
    push_interval: Duration,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
    standby: bool,
) {
    info!(
        %bind,
        auth_enabled = agent_token.is_some(),
        push_interval_seconds = push_interval.as_secs(),
        runtime_trusted_cidrs = runtime_trusted_cidrs.configured.len(),
        k8s_discovery_enabled = runtime_trusted_cidrs.k8s_discovery.is_some(),
        k8s_watch_timeout_seconds = K8S_WATCH_TIMEOUT.as_secs(),
        auto_refresh_interval_seconds = AUTO_REFRESH_INTERVAL.as_secs(),
        threat_missing_prefix_poll_interval_seconds = THREAT_MISSING_PREFIX_POLL_INTERVAL.as_secs(),
        standby,
        "xDS gRPC server listening"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args(cert: Option<&str>, key: Option<&str>, client_ca: Option<&str>) -> XdsTlsServerArgs {
        XdsTlsServerArgs {
            xds_tls_cert: cert.map(PathBuf::from),
            xds_tls_key: key.map(PathBuf::from),
            xds_tls_client_ca: client_ca.map(PathBuf::from),
        }
    }

    #[test]
    fn tls_disabled_by_default() {
        assert!(
            build_server_tls_config(&args(None, None, None))
                .expect("default args must not error")
                .is_none()
        );
    }

    #[test]
    fn cert_without_key_is_rejected() {
        let err = build_server_tls_config(&args(Some("cert.pem"), None, None))
            .expect_err("cert without key must fail");
        assert!(format!("{err:#}").contains("--xds-tls-cert"));
    }

    #[test]
    fn key_without_cert_is_rejected() {
        let err = build_server_tls_config(&args(None, Some("key.pem"), None))
            .expect_err("key without cert must fail");
        assert!(format!("{err:#}").contains("--xds-tls-key"));
    }

    #[test]
    fn client_ca_without_server_tls_is_rejected() {
        let err = build_server_tls_config(&args(None, None, Some("ca.pem")))
            .expect_err("client CA without server TLS must fail");
        assert!(format!("{err:#}").contains("--xds-tls-client-ca"));
    }
}
