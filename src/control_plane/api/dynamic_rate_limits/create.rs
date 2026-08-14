use super::input::{
    CreateDynamicRateLimitRequest, DynamicRateLimitInput, create_dynamic_rate_limit,
    dynamic_rate_limit_input,
};
use crate::control_plane::api::{
    ApiResult, ApiState, BatchRequest, CreateRows, Versioned, bump_policy_version_if_active,
    created_status, policy_version_after_optional_bump, validate_batch_len,
};
use crate::db::entities::dynamic_rate_limit;
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::TransactionTrait;

pub(in crate::control_plane::api) async fn create(
    State(state): State<ApiState>,
    Json(request): Json<CreateDynamicRateLimitRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<dynamic_rate_limit::Model>>)> {
    let txn = state.db.begin().await?;
    let created = create_dynamic_rate_limit(&txn, dynamic_rate_limit_input(request)?).await?;
    let bumped_version =
        bump_policy_version_if_active(&txn, created.inserted && created.row.enabled).await?;
    txn.commit().await?;
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    let row = created.row;
    Ok((
        created_status(created.inserted),
        Json(Versioned { version, data: row }),
    ))
}

pub(in crate::control_plane::api) async fn create_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchRequest<CreateDynamicRateLimitRequest>>,
) -> ApiResult<(StatusCode, Json<Versioned<Vec<dynamic_rate_limit::Model>>>)> {
    validate_batch_len(request.items.len())?;
    let inputs = request
        .items
        .into_iter()
        .map(dynamic_rate_limit_input)
        .collect::<ApiResult<Vec<_>>>()?;
    let txn = state.db.begin().await?;
    let summary = create_dynamic_rate_limit_rows(&txn, inputs).await?;
    let bumped_version = bump_policy_version_if_active(&txn, summary.active_changed).await?;
    txn.commit().await?;
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    Ok((
        created_status(summary.inserted),
        Json(Versioned {
            version,
            data: summary.rows,
        }),
    ))
}

async fn create_dynamic_rate_limit_rows(
    txn: &sea_orm::DatabaseTransaction,
    inputs: Vec<DynamicRateLimitInput>,
) -> ApiResult<CreateRows<dynamic_rate_limit::Model>> {
    let mut summary = CreateRows::with_capacity(inputs.len());
    for input in inputs {
        let created = create_dynamic_rate_limit(txn, input).await?;
        let active_changed = created.inserted && created.row.enabled;
        summary.push(created.row, created.inserted, active_changed);
    }
    Ok(summary)
}
