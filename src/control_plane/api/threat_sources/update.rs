use super::{
    delete::delete_threat_source_states_by_name, input::UpdateThreatSourceRequest,
    spawn_threat_refresh,
};
use crate::control_plane::api::{ApiError, ApiResult, ApiState, Versioned, current_policy_version};
use crate::{db, db::entities::threat_source, policy::model::DEFAULT_POLICY_NAME};
use axum::{
    Json,
    extract::{Path, State},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};

pub(in crate::control_plane::api) async fn update(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
    Json(request): Json<UpdateThreatSourceRequest>,
) -> ApiResult<Json<Versioned<threat_source::Model>>> {
    let row = load_threat_source(&state.db, id).await?;
    if row.enabled == request.enabled {
        return unchanged_threat_source_response(&state, row).await;
    }

    let source_name = row.name.clone();
    let txn = state.db.begin().await?;
    let row = update_threat_source_enabled(&txn, row, request.enabled).await?;
    if !request.enabled {
        delete_threat_source_states_by_name(&txn, std::iter::once(source_name.as_str())).await?;
    }
    let version = db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    txn.commit().await?;

    if request.enabled {
        spawn_threat_refresh(state.db.clone());
    }

    Ok(Json(Versioned { version, data: row }))
}

async fn load_threat_source(
    db: &sea_orm::DatabaseConnection,
    id: i32,
) -> ApiResult<threat_source::Model> {
    threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Id.eq(id))
        .one(db)
        .await?
        .ok_or_else(|| ApiError::not_found("threat source not found"))
}

async fn unchanged_threat_source_response(
    state: &ApiState,
    row: threat_source::Model,
) -> ApiResult<Json<Versioned<threat_source::Model>>> {
    Ok(Json(Versioned {
        version: current_policy_version(&state.db).await?,
        data: row,
    }))
}

async fn update_threat_source_enabled(
    txn: &sea_orm::DatabaseTransaction,
    row: threat_source::Model,
    enabled: bool,
) -> ApiResult<threat_source::Model> {
    let mut active: threat_source::ActiveModel = row.into();
    active.enabled = Set(enabled);
    active.updated_at = Set(chrono::Utc::now().naive_utc());
    Ok(active.update(txn).await?)
}
