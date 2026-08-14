use super::super::{
    ApiResult, ApiState, CachedGeoRefresh, GeoRefreshDecision, MANUAL_REFRESH_RATE_LIMIT,
    Versioned, current_policy_version,
};
use crate::intelligence::geo;
use anyhow::Result;
use axum::{Json, extract::State};
use sea_orm::DatabaseConnection;
use tracing::{info, warn};

pub(in crate::control_plane::api) async fn refresh(
    State(state): State<ApiState>,
) -> ApiResult<Json<Versioned<geo::GeoRefreshReport>>> {
    match state
        .geo_refresh_limiter
        .start_or_cached(MANUAL_REFRESH_RATE_LIMIT)
    {
        GeoRefreshDecision::Start { permit, previous } => {
            let db = state.db.clone();
            let geo_lookup = state.geo_lookup.clone();
            tokio::spawn(async move {
                let permit = permit;
                match run_geo_refresh(db, geo_lookup).await {
                    Ok(result) => {
                        info!(
                            version = result.version,
                            checked_countries = result.report.checked_country_count,
                            changed_countries = result.report.changed_country_count,
                            prefixes = result.report.prefix_count,
                            "country IP refresh completed"
                        );
                        permit.finish_success(result);
                    }
                    Err(err) => {
                        warn!(error = %err, "country IP refresh failed");
                    }
                }
            });
            geo_refresh_response(&state.db, previous, "running", true).await
        }
        GeoRefreshDecision::Running(cached) => {
            geo_refresh_response(&state.db, cached, "running", true).await
        }
        GeoRefreshDecision::RateLimited(cached) => {
            geo_refresh_response(&state.db, cached, "rate_limited", false).await
        }
    }
}

async fn geo_refresh_response(
    db: &DatabaseConnection,
    cached: Option<CachedGeoRefresh>,
    status: &str,
    running: bool,
) -> ApiResult<Json<Versioned<geo::GeoRefreshReport>>> {
    let version = cached
        .as_ref()
        .map_or(current_policy_version(db).await?, |cached| cached.version);
    let report = cached.map_or_else(
        || {
            geo_refresh_response_report(
                geo::GeoRefreshReport::empty(status),
                status,
                false,
                running,
            )
        },
        |cached| geo_refresh_response_report(cached.report, status, true, running),
    );
    Ok(Json(Versioned {
        version,
        data: report,
    }))
}

async fn run_geo_refresh(
    db: DatabaseConnection,
    geo_lookup: geo::GeoIpLookup,
) -> Result<CachedGeoRefresh> {
    let mut report = geo::refresh_all_ipdeny_lists(&db).await?;
    if report.changed_country_count > 0 {
        geo_lookup.rebuild_from_db(&db).await?;
    }
    let version = current_policy_version(&db).await?;
    let status = report.refresh_status.clone();
    let running = report.running;
    report = geo_refresh_response_report(report, &status, false, running);
    Ok(CachedGeoRefresh { version, report })
}

fn geo_refresh_response_report(
    mut report: geo::GeoRefreshReport,
    status: &str,
    cached: bool,
    running: bool,
) -> geo::GeoRefreshReport {
    report.refresh_status = status.to_string();
    report.cached = cached;
    report.running = running;
    report
}
