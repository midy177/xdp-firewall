use super::super::{ApiResult, validate_positive_i32};
use crate::{db::entities::dynamic_rate_limit, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ColumnTrait, QueryFilter};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct DynamicRateLimitQuery {
    pub(super) page: Option<u64>,
    pub(super) page_size: Option<u64>,
    enabled: Option<bool>,
    priority: Option<i32>,
    protocol: Option<String>,
    port: Option<i32>,
    packets_per_second: Option<i32>,
    burst: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct DynamicRateLimitMatchQuery {
    pub(super) enabled: bool,
    pub(super) priority: i32,
    pub(super) protocol: String,
    pub(super) port: i32,
    pub(super) packets_per_second: i32,
    pub(super) burst: i32,
}

impl DynamicRateLimitQuery {
    pub(super) fn apply_filters(
        self,
        mut select: sea_orm::Select<dynamic_rate_limit::Entity>,
    ) -> ApiResult<sea_orm::Select<dynamic_rate_limit::Entity>> {
        let protocol = self
            .protocol
            .as_deref()
            .map(super::super::normalize_protocol)
            .transpose()?;
        let port = super::super::validate_dynamic_rate_port(
            protocol.as_deref().unwrap_or("any"),
            self.port,
        )?;

        select = select.filter(dynamic_rate_limit::Column::PolicyName.eq(DEFAULT_POLICY_NAME));
        if let Some(enabled) = self.enabled {
            select = select.filter(dynamic_rate_limit::Column::Enabled.eq(enabled));
        }
        if let Some(priority) = self.priority {
            select = select.filter(dynamic_rate_limit::Column::Priority.eq(priority));
        }
        if let Some(protocol) = protocol {
            select = select.filter(dynamic_rate_limit::Column::Protocol.eq(protocol));
        }
        if let Some(port) = port {
            select = select.filter(dynamic_rate_limit::Column::Port.eq(port));
        }
        if let Some(packets_per_second) = self.packets_per_second {
            validate_positive_i32("packets_per_second", packets_per_second)?;
            select =
                select.filter(dynamic_rate_limit::Column::PacketsPerSecond.eq(packets_per_second));
        }
        if let Some(burst) = self.burst {
            validate_positive_i32("burst", burst)?;
            select = select.filter(dynamic_rate_limit::Column::Burst.eq(burst));
        }
        Ok(select)
    }
}
