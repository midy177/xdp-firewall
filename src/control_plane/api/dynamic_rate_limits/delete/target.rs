use super::super::query::DynamicRateLimitMatchQuery;
use crate::{
    control_plane::api::{ApiError, ApiResult, validate_positive_i32},
    db::entities::dynamic_rate_limit,
    policy::model::DEFAULT_POLICY_NAME,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

pub(super) struct DynamicRateLimitDeleteTarget {
    enabled: bool,
    priority: i32,
    protocol: String,
    port: i32,
    packets_per_second: i32,
    burst: i32,
}

impl DynamicRateLimitDeleteTarget {
    pub(super) fn from_query(query: DynamicRateLimitMatchQuery) -> ApiResult<Self> {
        let protocol = super::super::super::normalize_protocol(&query.protocol)?;
        let port = super::super::super::validate_dynamic_rate_port(&protocol, Some(query.port))?
            .ok_or_else(|| ApiError::bad_request("port is required"))?;
        validate_positive_i32("packets_per_second", query.packets_per_second)?;
        validate_positive_i32("burst", query.burst)?;
        Ok(Self {
            enabled: query.enabled,
            priority: query.priority,
            protocol,
            port,
            packets_per_second: query.packets_per_second,
            burst: query.burst,
        })
    }

    pub(super) fn select(&self) -> sea_orm::Select<dynamic_rate_limit::Entity> {
        self.apply_filters(dynamic_rate_limit::Entity::find())
    }

    pub(super) fn delete(&self) -> sea_orm::DeleteMany<dynamic_rate_limit::Entity> {
        self.apply_filters(dynamic_rate_limit::Entity::delete_many())
    }

    fn apply_filters<Q>(&self, query: Q) -> Q
    where
        Q: QueryFilter,
    {
        query
            .filter(dynamic_rate_limit::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
            .filter(dynamic_rate_limit::Column::Enabled.eq(self.enabled))
            .filter(dynamic_rate_limit::Column::Priority.eq(self.priority))
            .filter(dynamic_rate_limit::Column::Protocol.eq(&self.protocol))
            .filter(dynamic_rate_limit::Column::Port.eq(self.port))
            .filter(dynamic_rate_limit::Column::PacketsPerSecond.eq(self.packets_per_second))
            .filter(dynamic_rate_limit::Column::Burst.eq(self.burst))
    }
}
