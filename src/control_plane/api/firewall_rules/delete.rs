use super::super::{
    ApiError, ApiResult, ApiState, BatchDeleteResponse, Versioned, bump_policy_version_if_active,
    ensure_all_ids_deleted, policy_version_after_optional_bump,
};
use super::{
    input::{RuleBatchDeleteRequest, validate_batch_delete_request},
    query::RuleMatchQuery,
};
use crate::{db::entities::firewall_rule, policy::model::DEFAULT_POLICY_NAME};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, TransactionTrait};

pub(in crate::control_plane::api) async fn delete_by_id(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let txn = state.db.begin().await?;
    let row = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(firewall_rule::Column::Id.eq(id))
        .one(&txn)
        .await?
        .ok_or_else(|| ApiError::not_found("rule not found"))?;
    let deleted = firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(firewall_rule::Column::Id.eq(id))
        .exec(&txn)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("rule not found"));
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
    Json(request): Json<RuleBatchDeleteRequest>,
) -> ApiResult<Json<Versioned<BatchDeleteResponse>>> {
    let (ids, rule_keys) = validate_batch_delete_request(request)?;
    let txn = state.db.begin().await?;
    let targets = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(batch_delete_selector(&ids, &rule_keys))
        .all(&txn)
        .await?;
    let target_ids = targets.iter().map(|rule| rule.id).collect::<Vec<_>>();
    if target_ids.is_empty() {
        return Err(ApiError::not_found("rule not found"));
    }

    let deleted_active = targets.iter().any(|rule| rule.enabled);
    let deleted = firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(firewall_rule::Column::Id.is_in(target_ids.iter().copied()))
        .exec(&txn)
        .await?;
    ensure_all_ids_deleted(deleted.rows_affected, target_ids.len(), "rule not found")?;
    let bumped_version = bump_policy_version_if_active(&txn, deleted_active).await?;
    txn.commit().await?;

    Ok(Json(Versioned {
        version: policy_version_after_optional_bump(&state.db, bumped_version).await?,
        data: BatchDeleteResponse {
            deleted: deleted.rows_affected,
        },
    }))
}

pub(in crate::control_plane::api) async fn delete_by_query(
    State(state): State<ApiState>,
    Query(query): Query<RuleMatchQuery>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let selector = query.selector()?;
    let txn = state.db.begin().await?;
    let targets = firewall_rule::Entity::find()
        .filter(selector.clone())
        .all(&txn)
        .await?;
    if targets.is_empty() {
        return Err(ApiError::not_found("rule not found"));
    }

    let target_ids = targets.iter().map(|rule| rule.id).collect::<Vec<_>>();
    let deleted_active = targets.iter().any(|rule| rule.enabled);
    let deleted = firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::Id.is_in(target_ids))
        .exec(&txn)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("rule not found"));
    }
    let bumped_version = bump_policy_version_if_active(&txn, deleted_active).await?;
    txn.commit().await?;

    Ok(Json(Versioned {
        version: policy_version_after_optional_bump(&state.db, bumped_version).await?,
        data: serde_json::json!({ "deleted": deleted.rows_affected }),
    }))
}

fn batch_delete_selector(ids: &[i32], rule_keys: &[String]) -> Condition {
    let mut selector = Condition::any();
    if !ids.is_empty() {
        selector = selector.add(firewall_rule::Column::Id.is_in(ids.iter().copied()));
    }
    if !rule_keys.is_empty() {
        selector = selector.add(firewall_rule::Column::RuleKey.is_in(rule_keys.iter().cloned()));
    }
    selector
}
