use super::{
    super::{
        ApiError, ApiResult, ApiState, BatchRequest, CreateRows, Versioned,
        bump_policy_version_if_active, created_status, policy_version_after_optional_bump,
        validate_batch_len,
    },
    input::{
        CreateThreatSourceRequest, ThreatSourceInput, create_threat_source, threat_source_input,
    },
    spawn_threat_refresh, threat_source,
};
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::TransactionTrait;

pub(in crate::control_plane::api) async fn create(
    State(state): State<ApiState>,
    Json(request): Json<CreateThreatSourceRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<threat_source::Model>>)> {
    let txn = state.db.begin().await?;
    let summary = create_threat_source_rows(&txn, vec![threat_source_input(request)?]).await?;
    let bumped_version = bump_policy_version_if_active(&txn, summary.active_changed).await?;
    txn.commit().await?;
    if summary.active_changed {
        spawn_threat_refresh(state.db.clone());
    }
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    let row = summary
        .rows
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::conflict("threat source create produced no row"))?;
    Ok((
        created_status(summary.inserted),
        Json(Versioned { version, data: row }),
    ))
}

pub(in crate::control_plane::api) async fn create_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchRequest<CreateThreatSourceRequest>>,
) -> ApiResult<(StatusCode, Json<Versioned<Vec<threat_source::Model>>>)> {
    validate_batch_len(request.items.len())?;
    let inputs = request
        .items
        .into_iter()
        .map(threat_source_input)
        .collect::<ApiResult<Vec<_>>>()?;
    let txn = state.db.begin().await?;
    let summary = create_threat_source_rows(&txn, inputs).await?;
    let bumped_version = bump_policy_version_if_active(&txn, summary.active_changed).await?;
    txn.commit().await?;
    if summary.active_changed {
        spawn_threat_refresh(state.db.clone());
    }
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    Ok((
        created_status(summary.inserted),
        Json(Versioned {
            version,
            data: summary.rows,
        }),
    ))
}

async fn create_threat_source_rows(
    txn: &sea_orm::DatabaseTransaction,
    inputs: Vec<ThreatSourceInput>,
) -> ApiResult<CreateRows<threat_source::Model>> {
    let mut summary = CreateRows::with_capacity(inputs.len());
    for input in inputs {
        let created = create_threat_source(txn, input).await?;
        let active_changed = created.inserted && created.row.enabled;
        summary.push(created.row, created.inserted, active_changed);
    }
    Ok(summary)
}
