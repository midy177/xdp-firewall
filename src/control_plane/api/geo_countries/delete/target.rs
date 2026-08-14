use super::super::query::GeoCountryMatchQuery;
use crate::{
    control_plane::api::{ApiResult, normalize_action},
    db::entities::geo_country_policy,
    intelligence::geo,
    policy::model::DEFAULT_POLICY_NAME,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

pub(super) struct GeoCountryDeleteTarget {
    country: String,
    action: String,
    enabled: bool,
}

impl GeoCountryDeleteTarget {
    pub(super) fn from_query(query: GeoCountryMatchQuery) -> ApiResult<Self> {
        Ok(Self {
            country: geo::normalize_country(&query.country)?,
            action: normalize_action(&query.action)?,
            enabled: query.enabled,
        })
    }

    pub(super) fn select(&self) -> sea_orm::Select<geo_country_policy::Entity> {
        self.apply_filters(geo_country_policy::Entity::find())
    }

    pub(super) fn delete(&self) -> sea_orm::DeleteMany<geo_country_policy::Entity> {
        self.apply_filters(geo_country_policy::Entity::delete_many())
    }

    fn apply_filters<Q>(&self, query: Q) -> Q
    where
        Q: QueryFilter,
    {
        query
            .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
            .filter(geo_country_policy::Column::Country.eq(&self.country))
            .filter(geo_country_policy::Column::Action.eq(&self.action))
            .filter(geo_country_policy::Column::Enabled.eq(self.enabled))
    }
}
