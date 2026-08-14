use super::ApiResult;
use crate::{db::entities::trusted_cidr, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ColumnTrait, QueryFilter};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct TrustedCidrQuery {
    pub(super) page: Option<u64>,
    pub(super) page_size: Option<u64>,
    cidr: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct TrustedCidrMatchQuery {
    pub(super) cidr: String,
}

impl TrustedCidrQuery {
    pub(super) fn apply_filters(
        self,
        mut select: sea_orm::Select<trusted_cidr::Entity>,
    ) -> ApiResult<sea_orm::Select<trusted_cidr::Entity>> {
        select = select.filter(trusted_cidr::Column::PolicyName.eq(DEFAULT_POLICY_NAME));
        if let Some(cidr) = self.cidr.as_deref() {
            select =
                select.filter(trusted_cidr::Column::Cidr.eq(super::super::normalize_cidr(cidr)?));
        }
        if let Some(enabled) = self.enabled {
            select = select.filter(trusted_cidr::Column::Enabled.eq(enabled));
        }
        Ok(select)
    }
}
