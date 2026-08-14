use super::{
    ApiResult,
    input::{normalize_threat_format, validate_optional_non_negative},
};
use crate::{db::entities::threat_source, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ColumnTrait, QueryFilter};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct ThreatSourceQuery {
    pub(super) page: Option<u64>,
    pub(super) page_size: Option<u64>,
    name: Option<String>,
    url: Option<String>,
    format: Option<String>,
    enabled: Option<bool>,
    min_score: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct ThreatSourceMatchQuery {
    pub(super) name: String,
}

impl ThreatSourceQuery {
    pub(super) fn apply_filters(
        self,
        mut select: sea_orm::Select<threat_source::Entity>,
    ) -> ApiResult<sea_orm::Select<threat_source::Entity>> {
        select = select.filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME));
        if let Some(name) = self.name.as_deref() {
            select = select.filter(threat_source::Column::Name.eq(name.trim()));
        }
        if let Some(url) = self.url.as_deref() {
            select = select.filter(threat_source::Column::Url.eq(url.trim()));
        }
        if let Some(format) = self.format.as_deref() {
            select =
                select.filter(threat_source::Column::Format.eq(normalize_threat_format(format)?));
        }
        if let Some(enabled) = self.enabled {
            select = select.filter(threat_source::Column::Enabled.eq(enabled));
        }
        if let Some(min_score) = self.min_score {
            validate_optional_non_negative("min_score", Some(min_score))?;
            select = select.filter(threat_source::Column::MinScore.eq(min_score));
        }
        Ok(select)
    }
}
