use super::super::{ApiError, ApiResult, validate_positive_i32};
use crate::{db::entities::dynamic_rate_limit, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct CreateDynamicRateLimitRequest {
    enabled: Option<bool>,
    priority: i32,
    protocol: String,
    port: Option<i32>,
    packets_per_second: i32,
    burst: i32,
    comment: Option<String>,
}

pub(super) struct DynamicRateLimitInput {
    enabled: bool,
    priority: i32,
    protocol: String,
    port: Option<i32>,
    packets_per_second: i32,
    burst: i32,
    comment: Option<String>,
}

pub(super) struct DynamicRateLimitCreate {
    pub(super) row: dynamic_rate_limit::Model,
    pub(super) inserted: bool,
}

pub(super) fn dynamic_rate_limit_input(
    request: CreateDynamicRateLimitRequest,
) -> ApiResult<DynamicRateLimitInput> {
    let protocol = super::super::normalize_protocol(&request.protocol)?;
    let port = super::super::validate_dynamic_rate_port(protocol.as_str(), request.port)?;
    validate_positive_i32("packets_per_second", request.packets_per_second)?;
    validate_positive_i32("burst", request.burst)?;
    Ok(DynamicRateLimitInput {
        enabled: request.enabled.unwrap_or(true),
        priority: request.priority,
        protocol,
        port,
        packets_per_second: request.packets_per_second,
        burst: request.burst,
        comment: request.comment,
    })
}

pub(super) async fn create_dynamic_rate_limit<C>(
    db: &C,
    input: DynamicRateLimitInput,
) -> ApiResult<DynamicRateLimitCreate>
where
    C: ConnectionTrait,
{
    let mut select = dynamic_rate_limit::Entity::find()
        .filter(dynamic_rate_limit::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(dynamic_rate_limit::Column::Enabled.eq(input.enabled))
        .filter(dynamic_rate_limit::Column::Priority.eq(input.priority))
        .filter(dynamic_rate_limit::Column::Protocol.eq(&input.protocol))
        .filter(dynamic_rate_port_filter(input.port))
        .filter(dynamic_rate_limit::Column::PacketsPerSecond.eq(input.packets_per_second))
        .filter(dynamic_rate_limit::Column::Burst.eq(input.burst));
    select = match &input.comment {
        Some(comment) => select.filter(dynamic_rate_limit::Column::Comment.eq(comment)),
        None => select.filter(dynamic_rate_limit::Column::Comment.is_null()),
    };
    let existing = select.all(db).await?;
    match existing.len() {
        0 => {
            let row = active_model(input).insert(db).await?;
            Ok(DynamicRateLimitCreate {
                row,
                inserted: true,
            })
        }
        1 => {
            let row = existing
                .into_iter()
                .next()
                .ok_or_else(|| ApiError::conflict("dynamic rate limit match disappeared"))?;
            Ok(DynamicRateLimitCreate {
                row,
                inserted: false,
            })
        }
        _ => Err(ApiError::conflict(
            "multiple dynamic rate limits match; delete by id",
        )),
    }
}

fn active_model(input: DynamicRateLimitInput) -> dynamic_rate_limit::ActiveModel {
    dynamic_rate_limit::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(input.enabled),
        priority: Set(input.priority),
        protocol: Set(input.protocol),
        port: Set(input.port),
        packets_per_second: Set(input.packets_per_second),
        burst: Set(input.burst),
        comment: Set(input.comment),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
}

pub(super) fn dynamic_rate_port_filter(port: Option<i32>) -> sea_orm::Condition {
    match port {
        Some(port) => sea_orm::Condition::all().add(dynamic_rate_limit::Column::Port.eq(port)),
        None => sea_orm::Condition::all().add(dynamic_rate_limit::Column::Port.is_null()),
    }
}
