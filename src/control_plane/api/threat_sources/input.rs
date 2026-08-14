use crate::control_plane::api::{ApiError, ApiResult};
use crate::{
    db::entities::threat_source, intelligence::threat, policy::model::DEFAULT_POLICY_NAME,
};
use anyhow::{Result, bail};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct CreateThreatSourceRequest {
    enabled: Option<bool>,
    name: String,
    url: String,
    format: String,
    min_score: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct UpdateThreatSourceRequest {
    pub(super) enabled: bool,
}

pub(super) struct ThreatSourceInput {
    enabled: bool,
    name: String,
    url: String,
    format: String,
    min_score: Option<i32>,
}

pub(super) struct ThreatSourceCreate {
    pub(super) row: threat_source::Model,
    pub(super) inserted: bool,
}

pub(super) fn threat_source_input(
    request: CreateThreatSourceRequest,
) -> ApiResult<ThreatSourceInput> {
    let format = normalize_threat_format(&request.format)?;
    threat::validate_source_url(&request.url)?;
    validate_optional_non_negative("min_score", request.min_score)?;
    Ok(ThreatSourceInput {
        enabled: request.enabled.unwrap_or(true),
        name: request.name,
        url: request.url,
        format,
        min_score: request.min_score,
    })
}

pub(super) async fn create_threat_source<C>(
    db: &C,
    input: ThreatSourceInput,
) -> ApiResult<ThreatSourceCreate>
where
    C: ConnectionTrait,
{
    let existing = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Name.eq(&input.name))
        .one(db)
        .await?;
    let Some(existing) = existing else {
        let row = input.active_model().insert(db).await?;
        return Ok(ThreatSourceCreate {
            row,
            inserted: true,
        });
    };
    if input.matches_existing(&existing) {
        return Ok(ThreatSourceCreate {
            row: existing,
            inserted: false,
        });
    }
    Err(ApiError::conflict("threat source name already exists"))
}

impl ThreatSourceInput {
    fn active_model(self) -> threat_source::ActiveModel {
        threat_source::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(self.enabled),
            name: Set(self.name),
            url: Set(self.url),
            format: Set(self.format),
            min_score: Set(self.min_score),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
    }

    fn matches_existing(&self, row: &threat_source::Model) -> bool {
        row.enabled == self.enabled
            && row.url == self.url
            && row.format == self.format
            && row.min_score == self.min_score
    }
}

pub(super) fn normalize_threat_format(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "cidr" => Ok("cidr".to_string()),
        "ips" => Ok("ips".to_string()),
        "ipsum" => Ok("ipsum".to_string()),
        "voipbl" | "voipbl_cidr" | "voipbl-cidr" => Ok("voipbl".to_string()),
        "spamhaus_drop" | "spamhaus-drop" => Ok("spamhaus_drop".to_string()),
        _ => bail!("threat format must be cidr, ips, ipsum, voipbl, or spamhaus_drop"),
    }
}

pub(super) fn validate_optional_non_negative(label: &str, value: Option<i32>) -> Result<()> {
    if value.is_some_and(|value| value < 0) {
        bail!("{label} must be greater than or equal to 0");
    }
    Ok(())
}
