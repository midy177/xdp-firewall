use super::super::{
    ApiError, ApiResult, ApiState, BatchDeleteRequest, BatchDeleteResponse, Versioned,
    ensure_all_ids_deleted, validate_batch_ids,
};
use crate::{db, db::entities::temp_ban, policy::model::DEFAULT_POLICY_NAME};
use axum::{
    Json,
    extract::{Path, State},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

pub(in crate::control_plane::api) async fn delete_by_id(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let txn = state.db.begin().await?;
    let deleted = temp_ban::Entity::delete_many()
        .filter(temp_ban::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(temp_ban::Column::Id.eq(id))
        .exec(&txn)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("temporary ban not found"));
    }
    let version = db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    txn.commit().await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

pub(in crate::control_plane::api) async fn delete_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchDeleteRequest>,
) -> ApiResult<Json<Versioned<BatchDeleteResponse>>> {
    let ids = validate_batch_ids(request.ids)?;
    let txn = state.db.begin().await?;
    let deleted = temp_ban::Entity::delete_many()
        .filter(temp_ban::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(temp_ban::Column::Id.is_in(ids.iter().copied()))
        .exec(&txn)
        .await?;
    ensure_all_ids_deleted(deleted.rows_affected, ids.len(), "temporary ban not found")?;
    let version = db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    txn.commit().await?;
    Ok(Json(Versioned {
        version,
        data: BatchDeleteResponse {
            deleted: deleted.rows_affected,
        },
    }))
}
