use super::super::{
    ApiError, ApiResult, ApiState, BatchDeleteRequest, BatchDeleteResponse, Versioned,
    bump_policy_version_if_active, ensure_all_ids_deleted, policy_version_after_optional_bump,
    validate_batch_ids,
};
use super::query::GeoCountryMatchQuery;
use crate::{db::entities::geo_country_policy, policy::model::DEFAULT_POLICY_NAME};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

mod target;

use target::GeoCountryDeleteTarget;

pub(in crate::control_plane::api) async fn delete_by_query(
    State(state): State<ApiState>,
    Query(query): Query<GeoCountryMatchQuery>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let target = GeoCountryDeleteTarget::from_query(query)?;
    let txn = state.db.begin().await?;
    let targets = target.select().all(&txn).await?;
    if targets.len() > 1 {
        return Err(ApiError::conflict(
            "multiple geo country policies match; delete by id",
        ));
    }
    let deleted_active = targets
        .first()
        .ok_or_else(|| ApiError::not_found("geo country policy not found"))?
        .enabled;

    let deleted = target.delete().exec(&txn).await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("geo country policy not found"));
    }
    let bumped_version = bump_policy_version_if_active(&txn, deleted_active).await?;
    txn.commit().await?;

    Ok(Json(Versioned {
        version: policy_version_after_optional_bump(&state.db, bumped_version).await?,
        data: serde_json::json!({ "deleted": deleted.rows_affected }),
    }))
}

pub(in crate::control_plane::api) async fn delete_by_id(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let txn = state.db.begin().await?;
    let row = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Id.eq(id))
        .one(&txn)
        .await?
        .ok_or_else(|| ApiError::not_found("geo country policy not found"))?;
    let deleted = geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Id.eq(id))
        .exec(&txn)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("geo country policy not found"));
    }
    let bumped_version = bump_policy_version_if_active(&txn, row.enabled).await?;
    txn.commit().await?;

    Ok(Json(Versioned {
        version: policy_version_after_optional_bump(&state.db, bumped_version).await?,
        data: serde_json::json!({ "deleted": id }),
    }))
}

pub(in crate::control_plane::api) async fn delete_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchDeleteRequest>,
) -> ApiResult<Json<Versioned<BatchDeleteResponse>>> {
    let ids = validate_batch_ids(request.ids)?;
    let txn = state.db.begin().await?;
    let targets = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Id.is_in(ids.iter().copied()))
        .all(&txn)
        .await?;
    if targets.len() != ids.len() {
        return Err(ApiError::not_found("geo country policy not found"));
    }

    let deleted_active = targets.iter().any(|row| row.enabled);
    let deleted = geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Id.is_in(ids.iter().copied()))
        .exec(&txn)
        .await?;
    ensure_all_ids_deleted(
        deleted.rows_affected,
        ids.len(),
        "geo country policy not found",
    )?;
    let bumped_version = bump_policy_version_if_active(&txn, deleted_active).await?;
    txn.commit().await?;

    Ok(Json(Versioned {
        version: policy_version_after_optional_bump(&state.db, bumped_version).await?,
        data: BatchDeleteResponse {
            deleted: deleted.rows_affected,
        },
    }))
}
