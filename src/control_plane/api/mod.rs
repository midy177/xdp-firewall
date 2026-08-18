use super::xds;
use crate::{db, intelligence::geo};
use axum::{Json, extract::State};
use std::time::Duration;

const RUNTIME_TRUSTED_CIDRS_ENV: &str = "XDP_FIREWALL_TRUSTED_CIDRS";
const MANUAL_REFRESH_RATE_LIMIT: Duration = Duration::from_mins(5);
const MAX_BATCH_SIZE: usize = 500;

mod auth;
mod drop_events;
mod dynamic_defense;
mod dynamic_rate_limits;
mod error;
mod firewall_rules;
mod frontend;
mod geo_countries;
mod logging;
mod nodes;
mod pagination;
mod policy_meta;
mod response;
mod routes;
mod server;
mod standby;
mod state;
mod temp_bans;
mod threat_sources;
mod trusted_cidrs;
mod validation;

use error::{ApiError, ApiResult};
use logging::log_request;
use policy_meta::{
    bump_policy_version, bump_policy_version_if_active, current_policy_version, get_policy_version,
    policy_version_after_optional_bump, seed_example_policy,
};
use response::{
    BatchDeleteRequest, BatchDeleteResponse, BatchRequest, CreateRows, HealthResponse, Versioned,
    created_status,
};
use routes::router;
pub use server::serve;
use state::{
    ApiState, CachedGeoRefresh, CachedThreatRefresh, GeoRefreshDecision, GeoRefreshLimiter,
    ThreatRefreshDecision, ThreatRefreshLimiter,
};
pub(in crate::control_plane::api) use validation::{
    ensure_all_ids_deleted, normalize_action, normalize_cidr, normalize_protocol,
    parse_node_interface_ips, parse_normalized_cidr, reject_node_ip_block, validate_batch_ids,
    validate_batch_len, validate_dynamic_rate_port, validate_port, validate_positive_i32,
};

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn list_countries(State(state): State<ApiState>) -> ApiResult<Json<Vec<geo::CountryOption>>> {
    Ok(Json(geo::list_country_options(&state.db).await?))
}

async fn removed_multi_policy_api() -> ApiResult<()> {
    Err(ApiError::not_found(
        "multi-policy API is not supported; use single-policy endpoints",
    ))
}

#[cfg(test)]
mod tests;
