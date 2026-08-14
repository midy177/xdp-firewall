use super::super::{ApiResult, ApiState};
use anyhow::Context;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::debug;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct GeoLookupQuery {
    ip: String,
}

#[derive(Debug, Serialize)]
pub(in crate::control_plane::api) struct GeoLookupResponse {
    ip: String,
    country: Option<String>,
    country_name: Option<String>,
}

pub(in crate::control_plane::api) async fn lookup(
    State(state): State<ApiState>,
    Query(query): Query<GeoLookupQuery>,
) -> ApiResult<Json<GeoLookupResponse>> {
    let ip = parse_lookup_ip(&query.ip)?;
    let country = state.geo_lookup.lookup_country_record(ip);
    debug_lookup_result(ip, country.as_ref());
    Ok(Json(GeoLookupResponse {
        ip: ip.to_string(),
        country: country.as_ref().map(|country| country.code.clone()),
        country_name: country.and_then(|country| country.name),
    }))
}

fn parse_lookup_ip(value: &str) -> ApiResult<IpAddr> {
    Ok(value.trim().parse().with_context(|| {
        format!(
            "ip must be a valid IPv4 or IPv6 address, got '{}'",
            value.trim()
        )
    })?)
}

fn debug_lookup_result(ip: IpAddr, country: Option<&crate::intelligence::geo::GeoIpCountry>) {
    debug!(
        ip = %ip,
        hit = country.is_some(),
        country = country.map_or("-", |country| country.code.as_str()),
        country_name = country
            .and_then(|country| country.name.as_deref())
            .unwrap_or("-"),
        "geo IP lookup completed"
    );
}
