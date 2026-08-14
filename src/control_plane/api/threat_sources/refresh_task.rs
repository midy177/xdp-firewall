use crate::control_plane::api::{
    ApiResult, ApiState, CachedThreatRefresh, MANUAL_REFRESH_RATE_LIMIT, ThreatRefreshDecision,
    Versioned, current_policy_version,
};
use crate::intelligence::threat;
use anyhow::Result;
use axum::{Json, extract::State};
use sea_orm::DatabaseConnection;
use std::time::Duration;
use tracing::{info, warn};

pub(in crate::control_plane::api) async fn refresh(
    State(state): State<ApiState>,
) -> ApiResult<Json<Versioned<threat::ThreatRefreshReport>>> {
    let refresh_interval = if threat::enabled_threat_source_states_missing(&state.db).await? {
        Duration::ZERO
    } else {
        MANUAL_REFRESH_RATE_LIMIT
    };
    match state
        .threat_refresh_limiter
        .start_or_cached(refresh_interval)
    {
        ThreatRefreshDecision::Start { permit, previous } => {
            let db = state.db.clone();
            tokio::spawn(async move {
                let permit = permit;
                match run_threat_refresh(db).await {
                    Ok(result) => {
                        info!(
                            version = result.version,
                            enabled_threat_sources = result.report.enabled_source_count,
                            changed_threat_sources = result.report.changed_source_count,
                            prefixes = result.report.prefix_count,
                            "threat intelligence refresh completed"
                        );
                        permit.finish_success(result);
                    }
                    Err(err) => {
                        warn!(error = %err, "threat intelligence refresh failed");
                    }
                }
            });
            threat_refresh_response(&state.db, previous, "running", true).await
        }
        ThreatRefreshDecision::Running(cached) => {
            threat_refresh_response(&state.db, cached, "running", true).await
        }
        ThreatRefreshDecision::RateLimited(cached) => {
            threat_refresh_response(&state.db, cached, "rate_limited", false).await
        }
    }
}

async fn threat_refresh_response(
    db: &DatabaseConnection,
    cached: Option<CachedThreatRefresh>,
    status: &str,
    running: bool,
) -> ApiResult<Json<Versioned<threat::ThreatRefreshReport>>> {
    let version = cached
        .as_ref()
        .map_or(current_policy_version(db).await?, |cached| cached.version);
    let report = cached.map_or_else(
        || {
            threat_refresh_response_report(
                threat::ThreatRefreshReport::empty(status),
                status,
                false,
                running,
            )
        },
        |cached| threat_refresh_response_report(cached.report, status, true, running),
    );
    Ok(Json(Versioned {
        version,
        data: report,
    }))
}

pub(in crate::control_plane::api::threat_sources) async fn run_threat_refresh(
    db: DatabaseConnection,
) -> Result<CachedThreatRefresh> {
    let mut report = threat::refresh_enabled_threat_sources(&db).await?;
    let version = current_policy_version(&db).await?;
    let status = report.refresh_status.clone();
    let running = report.running;
    report = threat_refresh_response_report(report, &status, false, running);
    Ok(CachedThreatRefresh { version, report })
}

fn threat_refresh_response_report(
    mut report: threat::ThreatRefreshReport,
    status: &str,
    cached: bool,
    running: bool,
) -> threat::ThreatRefreshReport {
    report.refresh_status = status.to_string();
    report.cached = cached;
    report.running = running;
    report
}
