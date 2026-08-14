use super::super::ApiResult;
use crate::{db::entities::temp_ban, policy::model::DEFAULT_POLICY_NAME};
use anyhow::Context;
use sea_orm::Set;
use serde::Deserialize;

const DEFAULT_TEMP_BAN_SECONDS: i64 = 300;
const MAX_TEMP_BAN_SECONDS: i64 = 31_536_000;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct CreateTempBanRequest {
    pub(super) cidr: String,
    protocol: Option<String>,
    port: Option<i32>,
    duration_seconds: Option<i64>,
    comment: Option<String>,
}

pub(in crate::control_plane::api) fn active_model(
    request: CreateTempBanRequest,
) -> ApiResult<temp_ban::ActiveModel> {
    let cidr = super::super::normalize_cidr(&request.cidr)?;
    let protocol = request
        .protocol
        .as_deref()
        .map(super::super::normalize_protocol)
        .transpose()?
        .unwrap_or_else(|| "any".to_string());
    let port = super::super::validate_dynamic_rate_port(protocol.as_str(), request.port)?;
    let duration_seconds = validate_duration(request.duration_seconds)?;
    let now = chrono::Utc::now().naive_utc();
    let expires_at = now
        .checked_add_signed(chrono::Duration::seconds(duration_seconds))
        .context("temporary ban expiration overflowed")?;
    Ok(temp_ban::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        cidr: Set(cidr),
        protocol: Set(protocol),
        port: Set(port),
        expires_at: Set(expires_at),
        comment: Set(request.comment),
        created_at: Set(now),
        ..Default::default()
    })
}

fn validate_duration(value: Option<i64>) -> anyhow::Result<i64> {
    let duration = value.unwrap_or(DEFAULT_TEMP_BAN_SECONDS);
    if duration <= 0 {
        anyhow::bail!("duration_seconds must be greater than 0");
    }
    if duration > MAX_TEMP_BAN_SECONDS {
        anyhow::bail!("duration_seconds must be less than or equal to {MAX_TEMP_BAN_SECONDS}");
    }
    Ok(duration)
}
