use super::{
    AUTO_REFRESH_INTERVAL, DropEventHub, K8S_WATCH_TIMEOUT, TEMP_BAN_CLEANUP_INTERVAL,
    THREAT_MISSING_PREFIX_POLL_INTERVAL, XDS_MAX_MESSAGE_SIZE, XdsService,
    auth::reject_unsafe_unauthenticated_bind,
    k8s,
    proto::firewall_xds_server::FirewallXdsServer,
    refresh::TempBanCleanup,
    runtime_cidrs::{RuntimeTrustedCidrs, normalize_runtime_trusted_cidrs},
};
use crate::{cli::XdsArgs, intelligence::geo};
use anyhow::{Context, Result};
use sea_orm::DatabaseConnection;
use std::{net::SocketAddr, time::Duration};
use tonic::transport::Server;
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

    Server::builder()
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
