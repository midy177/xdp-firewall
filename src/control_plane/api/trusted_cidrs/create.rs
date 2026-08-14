use super::input::{CreateTrustedCidrRequest, upsert};
use crate::control_plane::api::{
    ApiResult, ApiState, BatchRequest, CreateRows, Versioned, bump_policy_version_if_active,
    created_status, policy_version_after_optional_bump, validate_batch_len,
};
use crate::db::entities::trusted_cidr;
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::TransactionTrait;

pub(in crate::control_plane::api) async fn create(
    State(state): State<ApiState>,
    Json(request): Json<CreateTrustedCidrRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<trusted_cidr::Model>>)> {
    let cidr = super::super::normalize_cidr(&request.cidr)?;
    let txn = state.db.begin().await?;
    let result = upsert(&txn, request, Some(cidr)).await?;
    let bumped_version = bump_policy_version_if_active(&txn, result.active_changed).await?;
    txn.commit().await?;
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    Ok((
        created_status(result.inserted),
        Json(Versioned {
            version,
            data: result.row,
        }),
    ))
}

pub(in crate::control_plane::api) async fn create_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchRequest<CreateTrustedCidrRequest>>,
) -> ApiResult<(StatusCode, Json<Versioned<Vec<trusted_cidr::Model>>>)> {
    validate_batch_len(request.items.len())?;
    let txn = state.db.begin().await?;
    let summary = create_trusted_cidr_rows(&txn, request.items).await?;
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

async fn create_trusted_cidr_rows(
    txn: &sea_orm::DatabaseTransaction,
    requests: Vec<CreateTrustedCidrRequest>,
) -> ApiResult<CreateRows<trusted_cidr::Model>> {
    let mut summary = CreateRows::with_capacity(requests.len());
    for request in requests {
        let result = upsert(txn, request, None).await?;
        summary.push(result.row, result.inserted, result.active_changed);
    }
    Ok(summary)
}
