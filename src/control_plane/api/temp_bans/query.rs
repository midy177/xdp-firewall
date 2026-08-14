use super::super::{ApiResult, pagination::PaginationQuery};
use crate::{db::entities::temp_ban, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ColumnTrait, QueryFilter, Select};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct TempBanQuery {
    page: Option<u64>,
    page_size: Option<u64>,
    cidr: Option<String>,
    protocol: Option<String>,
    port: Option<i32>,
}

impl TempBanQuery {
    pub(super) fn pagination(&self) -> PaginationQuery {
        PaginationQuery {
            page: self.page,
            page_size: self.page_size,
        }
    }

    pub(super) fn apply_filters(
        &self,
        select: Select<temp_ban::Entity>,
    ) -> ApiResult<Select<temp_ban::Entity>> {
        let protocol = self.normalized_protocol()?;
        let port = super::super::validate_dynamic_rate_port(
            protocol.as_deref().unwrap_or("any"),
            self.port,
        )?;
        let mut select = select
            .filter(temp_ban::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
            .filter(temp_ban::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()));
        if let Some(cidr) = self.cidr.as_deref() {
            select = select.filter(temp_ban::Column::Cidr.eq(super::super::normalize_cidr(cidr)?));
        }
        if let Some(protocol) = protocol {
            select = select.filter(temp_ban::Column::Protocol.eq(protocol));
        }
        if let Some(port) = port {
            select = select.filter(temp_ban::Column::Port.eq(port));
        }
        Ok(select)
    }

    fn normalized_protocol(&self) -> ApiResult<Option<String>> {
        self.protocol
            .as_deref()
            .filter(|value| *value != "all")
            .map(super::super::normalize_protocol)
            .transpose()
            .map_err(Into::into)
    }
}
