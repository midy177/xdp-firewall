use super::input::{CreateRuleRequest, RuleInput, create_rule, deny_rule_cidr, rule_input};
use crate::control_plane::api::{
    ApiResult, ApiState, BatchRequest, CreateRows, Versioned, bump_policy_version_if_active,
    created_status, policy_version_after_optional_bump, validate_batch_len,
};
use crate::db::entities::firewall_rule;
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::TransactionTrait;

pub(in crate::control_plane::api) async fn create(
    State(state): State<ApiState>,
    Json(request): Json<CreateRuleRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<firewall_rule::Model>>)> {
    reject_deny_rule_node_ip(&state, &request).await?;
    let txn = state.db.begin().await?;
    let created = create_rule(&txn, rule_input(request)?).await?;
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
    Json(request): Json<BatchRequest<CreateRuleRequest>>,
) -> ApiResult<(StatusCode, Json<Versioned<Vec<firewall_rule::Model>>>)> {
    validate_batch_len(request.items.len())?;
    for item in &request.items {
        reject_deny_rule_node_ip(&state, item).await?;
    }
    let inputs = request
        .items
        .into_iter()
        .map(rule_input)
        .collect::<ApiResult<Vec<_>>>()?;
    let txn = state.db.begin().await?;
    let summary = create_rule_rows(&txn, inputs).await?;
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

async fn reject_deny_rule_node_ip(state: &ApiState, request: &CreateRuleRequest) -> ApiResult<()> {
    if let Some(cidr) = deny_rule_cidr(request)? {
        super::super::reject_node_ip_block(&state.db, cidr, "deny rule").await?;
    }
    Ok(())
}

async fn create_rule_rows(
    txn: &sea_orm::DatabaseTransaction,
    inputs: Vec<RuleInput>,
) -> ApiResult<CreateRows<firewall_rule::Model>> {
    let mut summary = CreateRows::with_capacity(inputs.len());
    for input in inputs {
        let created = create_rule(txn, input).await?;
        let active_changed = created.inserted && created.row.enabled;
        summary.push(created.row, created.inserted, active_changed);
    }
    Ok(summary)
}
