use super::{ApiResult, ApiState, Versioned, current_policy_version, db};
use crate::db::entities::dynamic_defense;
use crate::policy::model::{DEFAULT_POLICY_NAME, DynamicDefensePolicy};
use crate::policy::validate;
use axum::{Json, extract::State};
use sea_orm::{ActiveModelTrait, EntityTrait, Set, TransactionTrait};

mod input;
mod model;

use input::{UpdateDynamicDefenseRequest, dynamic_defense_policy_from_request};
use model::{
    dynamic_defense_active_model, dynamic_defense_policy_from_model, set_dynamic_defense_fields,
};

pub(super) async fn get(State(state): State<ApiState>) -> ApiResult<Json<DynamicDefensePolicy>> {
    let data = dynamic_defense::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&state.db)
        .await?
        .as_ref()
        .map(dynamic_defense_policy_from_model)
        .transpose()?
        .unwrap_or_default();
    Ok(Json(data))
}

pub(super) async fn update(
    State(state): State<ApiState>,
    Json(request): Json<UpdateDynamicDefenseRequest>,
) -> ApiResult<Json<Versioned<DynamicDefensePolicy>>> {
    let data = dynamic_defense_policy_from_request(&request)?;
    validate::validate_dynamic_defense_policy(&data)?;
    let now = chrono::Utc::now().naive_utc();
    let txn = state.db.begin().await?;
    let existing = dynamic_defense::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
        .one(&txn)
        .await?;

    if let Some(row) = existing {
        if dynamic_defense_policy_from_model(&row)? == data {
            txn.rollback().await?;
            return Ok(Json(Versioned {
                version: current_policy_version(&state.db).await?,
                data,
            }));
        }
        let mut active: dynamic_defense::ActiveModel = row.into();
        set_dynamic_defense_fields(&mut active, &data)?;
        active.updated_at = Set(now);
        active.update(&txn).await?;
    } else {
        dynamic_defense_active_model(DEFAULT_POLICY_NAME, &data, now)?
            .insert(&txn)
            .await?;
    }

    let version = db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    txn.commit().await?;
    Ok(Json(Versioned { version, data }))
}
