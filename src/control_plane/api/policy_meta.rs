use super::{ApiResult, ApiState, Versioned, db};
use crate::cli::SeedExampleArgs;
use crate::db::entities::policy_version;
use crate::policy::{
    firewall,
    model::{DEFAULT_POLICY_NAME, PolicySnapshot},
    seed,
};
use anyhow::Result;
use axum::{Json, extract::State};
use sea_orm::{ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait, QueryFilter};

#[derive(Debug, serde::Serialize)]
pub(super) struct PolicyVersionResponse {
    version: i64,
}

pub(super) async fn current_policy_version(db: &DatabaseConnection) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

pub(super) async fn bump_policy_version_if_active(
    txn: &DatabaseTransaction,
    active_changed: bool,
) -> Result<Option<i64>> {
    if active_changed {
        Ok(Some(
            db::next_policy_version_in_transaction(txn, DEFAULT_POLICY_NAME).await?,
        ))
    } else {
        Ok(None)
    }
}

pub(super) async fn policy_version_after_optional_bump(
    db: &DatabaseConnection,
    bumped_version: Option<i64>,
) -> Result<i64> {
    match bumped_version {
        Some(version) => Ok(version),
        None => current_policy_version(db).await,
    }
}

/// Returns only the current policy version. Clients that just need to detect a
/// policy change use this instead of loading the full snapshot, which would
/// include the large `GeoIP` prefix list.
pub(super) async fn get_policy_version(
    State(state): State<ApiState>,
) -> ApiResult<Json<PolicyVersionResponse>> {
    Ok(Json(PolicyVersionResponse {
        version: current_policy_version(&state.db).await?,
    }))
}

pub(super) async fn bump_policy_version(
    State(state): State<ApiState>,
) -> ApiResult<Json<Versioned<PolicySnapshot>>> {
    let version = db::next_policy_version(&state.db, DEFAULT_POLICY_NAME).await?;
    let snapshot = firewall::load_policy(&state.db, DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: snapshot,
    }))
}

pub(super) async fn seed_example_policy(
    State(state): State<ApiState>,
) -> ApiResult<Json<Versioned<PolicySnapshot>>> {
    seed::seed_example_policy(&state.db, SeedExampleArgs {}).await?;
    let snapshot = firewall::load_policy(&state.db, DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version: snapshot.version,
        data: snapshot,
    }))
}
