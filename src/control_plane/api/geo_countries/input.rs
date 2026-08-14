use super::super::{ApiError, ApiResult, normalize_action};
use crate::{
    db::entities::geo_country_policy, intelligence::geo, policy::model::DEFAULT_POLICY_NAME,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct CreateGeoCountryRequest {
    enabled: Option<bool>,
    country: String,
    action: String,
}

pub(super) struct GeoCountryInput {
    enabled: bool,
    country: String,
    action: String,
}

pub(super) struct GeoCountryCreate {
    pub(super) row: geo_country_policy::Model,
    pub(super) inserted: bool,
}

pub(super) fn geo_country_input(request: &CreateGeoCountryRequest) -> ApiResult<GeoCountryInput> {
    let country = geo::normalize_country(&request.country)?;
    let action = normalize_action(&request.action)?;
    Ok(GeoCountryInput {
        enabled: request.enabled.unwrap_or(true),
        country,
        action,
    })
}

pub(super) async fn create_geo_country<C>(
    db: &C,
    input: GeoCountryInput,
) -> ApiResult<GeoCountryCreate>
where
    C: ConnectionTrait,
{
    let existing = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Enabled.eq(input.enabled))
        .filter(geo_country_policy::Column::Country.eq(&input.country))
        .filter(geo_country_policy::Column::Action.eq(&input.action))
        .all(db)
        .await?;
    match existing.len() {
        0 => {
            let row = geo_country_active_model(input).insert(db).await?;
            Ok(GeoCountryCreate {
                row,
                inserted: true,
            })
        }
        1 => {
            let row = existing
                .into_iter()
                .next()
                .ok_or_else(|| ApiError::conflict("geo country policy match disappeared"))?;
            Ok(GeoCountryCreate {
                row,
                inserted: false,
            })
        }
        _ => Err(ApiError::conflict(
            "multiple geo country policies match; delete by id",
        )),
    }
}

fn geo_country_active_model(input: GeoCountryInput) -> geo_country_policy::ActiveModel {
    geo_country_policy::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(input.enabled),
        country: Set(input.country),
        action: Set(input.action),
        packets_per_second: Set(None),
        burst: Set(None),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
}
