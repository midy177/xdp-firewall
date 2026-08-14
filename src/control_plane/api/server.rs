use super::{
    ApiState, GeoRefreshLimiter, RUNTIME_TRUSTED_CIDRS_ENV, ThreatRefreshLimiter, router, xds,
};
use crate::{cli::ApiArgs, intelligence::geo};
use anyhow::{Context, Result};
use sea_orm::DatabaseConnection;
use std::{collections::HashSet, net::SocketAddr};
use tracing::{debug, info, warn};

pub async fn serve(
    db: DatabaseConnection,
    args: ApiArgs,
    drop_events: xds::DropEventHub,
    geo_lookup: geo::GeoIpLookup,
) -> Result<()> {
    let bind = args
        .bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid API bind address '{}'", args.bind))?;
    let api_token = super::super::auth::api_token_from_env();
    let allow_unauthenticated = super::super::auth::allow_unauthenticated_from_env();
    log_runtime_trusted_cidr_config(&args);
    super::super::auth::reject_unsafe_unauthenticated_bind(
        bind,
        api_token.as_deref(),
        allow_unauthenticated,
    )?;

    let auth_enabled = api_token.is_some();
    let app = router(ApiState {
        db,
        api_token,
        drop_events,
        geo_lookup,
        geo_refresh_limiter: GeoRefreshLimiter::default(),
        threat_refresh_limiter: ThreatRefreshLimiter::default(),
    });
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind API listener on {bind}"))?;
    if allow_unauthenticated {
        warn!(
            %bind,
            auth_enabled,
            "API unauthenticated override is enabled; do not use this on untrusted networks"
        );
    }
    info!(
        %bind,
        auth_enabled,
        allow_unauthenticated,
        "API server listening"
    );
    axum::serve(listener, app)
        .await
        .context("API server failed")
}

fn log_runtime_trusted_cidr_config(args: &ApiArgs) {
    let env_runtime_trusted_cidrs = std::env::var(RUNTIME_TRUSTED_CIDRS_ENV).ok();
    let env_runtime_trusted_cidrs_values = env_runtime_trusted_cidrs
        .as_ref()
        .map(|value| configured_runtime_trusted_cidr_values(std::slice::from_ref(value)))
        .unwrap_or_default();
    let configured_runtime_trusted_cidrs =
        configured_runtime_trusted_cidr_values(&args.trusted_cidrs);
    debug!(
        api_env_runtime_trusted_cidrs = %env_runtime_trusted_cidrs_values.join(","),
        api_env_runtime_trusted_cidr_count = env_runtime_trusted_cidrs_values.len(),
        api_runtime_trusted_cidrs_env_present = env_runtime_trusted_cidrs.is_some(),
        api_clap_runtime_trusted_cidrs = %configured_runtime_trusted_cidrs.join(","),
        api_clap_runtime_trusted_cidr_count = configured_runtime_trusted_cidrs.len(),
        api_runtime_trusted_cidrs_config_source = concat!("--trusted-cidr/", "XDP_FIREWALL_TRUSTED_CIDRS"),
        "API observed runtime trusted CIDR config"
    );
}

fn configured_runtime_trusted_cidr_values(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut cidrs = Vec::new();
    for value in values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if seen.insert(value.to_string()) {
            cidrs.push(value.to_string());
        }
    }
    cidrs
}
