use super::super::{
    ApiError, ApiResult, ApiState, BatchDeleteRequest, BatchDeleteResponse, Versioned,
    bump_policy_version_if_active, ensure_all_ids_deleted, policy_version_after_optional_bump,
    validate_batch_ids,
};
use super::query::ThreatSourceMatchQuery;
use crate::{
    db::entities::{threat_source, threat_source_state},
    intelligence::threat,
    policy::model::DEFAULT_POLICY_NAME,
};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};

pub(in crate::control_plane::api) async fn delete_by_query(
    State(state): State<ApiState>,
    Query(query): Query<ThreatSourceMatchQuery>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let name = query.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }

    let txn = state.db.begin().await?;
    let row = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Name.eq(name))
        .one(&txn)
        .await?
        .ok_or_else(|| ApiError::not_found("threat source not found"))?;
    let deleted = threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Name.eq(name))
        .exec(&txn)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("threat source not found"));
    }
    delete_threat_source_states_by_name(&txn, std::iter::once(name)).await?;
    let bumped_version = bump_policy_version_if_active(&txn, row.enabled).await?;
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
    let row = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Id.eq(id))
        .one(&txn)
        .await?
        .ok_or_else(|| ApiError::not_found("threat source not found"))?;

    let deleted = threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Id.eq(id))
        .exec(&txn)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("threat source not found"));
    }
    delete_threat_source_states_by_name(&txn, std::iter::once(row.name.as_str())).await?;
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
    let rows = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Id.is_in(ids.iter().copied()))
        .all(&txn)
        .await?;
    if rows.len() != ids.len() {
        return Err(ApiError::not_found("threat source not found"));
    }

    let names = rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>();
    let deleted_enabled = rows.iter().any(|row| row.enabled);
    let deleted = threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Id.is_in(ids.iter().copied()))
        .exec(&txn)
        .await?;
    ensure_all_ids_deleted(deleted.rows_affected, ids.len(), "threat source not found")?;
    delete_threat_source_states_by_name(&txn, names).await?;
    let bumped_version = bump_policy_version_if_active(&txn, deleted_enabled).await?;
    txn.commit().await?;

    Ok(Json(Versioned {
        version: policy_version_after_optional_bump(&state.db, bumped_version).await?,
        data: BatchDeleteResponse {
            deleted: deleted.rows_affected,
        },
    }))
}

pub(super) async fn delete_threat_source_states_by_name<'a, I>(
    db: &impl ConnectionTrait,
    names: I,
) -> ApiResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let names = names.into_iter().collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(());
    }
    threat_source_state::Entity::delete_many()
        .filter(threat_source_state::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source_state::Column::SourceName.is_in(names.iter().copied()))
        .exec(db)
        .await?;
    threat::delete_persisted_threat_prefixes_by_name(db, names.iter().copied()).await?;
    Ok(())
}
