use super::super::{ApiResult, normalize_action};
use crate::{
    db::entities::geo_country_policy, intelligence::geo, policy::model::DEFAULT_POLICY_NAME,
};
use sea_orm::{ColumnTrait, QueryFilter};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct GeoCountryQuery {
    pub(super) page: Option<u64>,
    pub(super) page_size: Option<u64>,
    country: Option<String>,
    action: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct GeoCountryMatchQuery {
    pub(super) country: String,
    pub(super) action: String,
    pub(super) enabled: bool,
}

impl GeoCountryQuery {
    pub(super) fn apply_filters(
        self,
        mut select: sea_orm::Select<geo_country_policy::Entity>,
    ) -> ApiResult<sea_orm::Select<geo_country_policy::Entity>> {
        select = select.filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME));
        if let Some(country) = self.country.as_deref() {
            select = select
                .filter(geo_country_policy::Column::Country.eq(geo::normalize_country(country)?));
        }
        if let Some(action) = self.action.as_deref() {
            select =
                select.filter(geo_country_policy::Column::Action.eq(normalize_action(action)?));
        }
        if let Some(enabled) = self.enabled {
            select = select.filter(geo_country_policy::Column::Enabled.eq(enabled));
        }
        Ok(select)
    }
}
