use super::input::{CreateTempBanRequest, active_model};
use crate::control_plane::api::{ApiResult, ApiState, BatchRequest, Versioned, validate_batch_len};
use crate::{db, db::entities::temp_ban, policy::model::DEFAULT_POLICY_NAME};
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::{ActiveModelTrait, TransactionTrait};

pub(in crate::control_plane::api) async fn create(
    State(state): State<ApiState>,
    Json(request): Json<CreateTempBanRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<temp_ban::Model>>)> {
    reject_temp_ban_node_ip(&state, &request).await?;
    let txn = state.db.begin().await?;
    let row = active_model(request)?.insert(&txn).await?;
    let version = db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

pub(in crate::control_plane::api) async fn create_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchRequest<CreateTempBanRequest>>,
) -> ApiResult<(StatusCode, Json<Versioned<Vec<temp_ban::Model>>>)> {
    validate_batch_len(request.items.len())?;
    for item in &request.items {
        reject_temp_ban_node_ip(&state, item).await?;
    }
    let models = request
        .items
        .into_iter()
        .map(active_model)
        .collect::<ApiResult<Vec<_>>>()?;
    let txn = state.db.begin().await?;
    let mut rows = Vec::with_capacity(models.len());
    for model in models {
        rows.push(model.insert(&txn).await?);
    }
    let version = db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    txn.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(Versioned {
            version,
            data: rows,
        }),
    ))
}

async fn reject_temp_ban_node_ip(
    state: &ApiState,
    request: &CreateTempBanRequest,
) -> ApiResult<()> {
    super::super::reject_node_ip_block(
        &state.db,
        super::super::parse_normalized_cidr(&request.cidr)?,
        "temporary ban",
    )
    .await
}
