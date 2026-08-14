use super::super::{ApiError, ApiResult};
use super::input::normalize_rule_key;
use crate::control_plane::api::pagination::PaginationQuery;
use crate::{db::entities::firewall_rule, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ColumnTrait, Condition, QueryFilter};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct RuleQuery {
    page: Option<u64>,
    page_size: Option<u64>,
    rule_key: Option<String>,
    action: Option<String>,
    cidr: Option<String>,
    protocol: Option<String>,
    port: Option<i32>,
    priority: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct RuleMatchQuery {
    rule_key: Option<String>,
    action: Option<String>,
    cidr: Option<String>,
    protocol: Option<String>,
    port: Option<i32>,
    priority: Option<i32>,
}

impl RuleQuery {
    pub(super) fn pagination(&self) -> PaginationQuery {
        PaginationQuery {
            page: self.page,
            page_size: self.page_size,
        }
    }

    pub(super) fn apply_filters(
        self,
        mut select: sea_orm::Select<firewall_rule::Entity>,
    ) -> ApiResult<sea_orm::Select<firewall_rule::Entity>> {
        select = select.filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME));

        if let Some(action) = self.action.as_deref() {
            select = select
                .filter(firewall_rule::Column::Action.eq(super::super::normalize_action(action)?));
        }
        if let Some(rule_key) = normalize_rule_key(self.rule_key)? {
            select = select.filter(firewall_rule::Column::RuleKey.eq(rule_key));
        }
        if let Some(cidr) = self.cidr.as_deref() {
            select =
                select.filter(firewall_rule::Column::Cidr.eq(super::super::normalize_cidr(cidr)?));
        }

        let protocol = self
            .protocol
            .as_deref()
            .map(super::super::normalize_protocol)
            .transpose()?;
        let port = super::super::validate_port(protocol.as_deref(), self.port)?;

        if let Some(priority) = self.priority {
            select = select.filter(firewall_rule::Column::Priority.eq(priority));
        }
        if let Some(protocol) = protocol.as_deref() {
            select = select.filter(protocol_filter(protocol));
        }
        if let Some(port) = port {
            select = select.filter(firewall_rule::Column::Port.eq(port));
        }

        Ok(select)
    }
}

impl RuleMatchQuery {
    pub(super) fn selector(self) -> ApiResult<Condition> {
        let mut selector =
            Condition::all().add(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME));

        if let Some(rule_key) = normalize_rule_key(self.rule_key)? {
            return Ok(selector.add(firewall_rule::Column::RuleKey.eq(rule_key)));
        }

        let priority = self
            .priority
            .ok_or_else(|| ApiError::bad_request("rule_key or priority is required"))?;
        let action = super::super::normalize_action(
            self.action
                .as_deref()
                .ok_or_else(|| ApiError::bad_request("rule_key or action is required"))?,
        )?;
        let cidr = super::super::normalize_cidr(
            self.cidr
                .as_deref()
                .ok_or_else(|| ApiError::bad_request("rule_key or cidr is required"))?,
        )?;
        let protocol = super::super::normalize_protocol(
            self.protocol
                .as_deref()
                .ok_or_else(|| ApiError::bad_request("rule_key or protocol is required"))?,
        )?;
        let port_value = self
            .port
            .ok_or_else(|| ApiError::bad_request("rule_key or port is required"))?;
        let port = super::super::validate_port(Some(&protocol), Some(port_value))?
            .ok_or_else(|| ApiError::bad_request("rule_key or port is required"))?;

        selector = selector
            .add(firewall_rule::Column::Priority.eq(priority))
            .add(firewall_rule::Column::Action.eq(action))
            .add(firewall_rule::Column::Cidr.eq(cidr))
            .add(protocol_filter(&protocol))
            .add(firewall_rule::Column::Port.eq(port));

        Ok(selector)
    }
}

fn protocol_filter(protocol: &str) -> Condition {
    if protocol == "any" {
        Condition::any()
            .add(firewall_rule::Column::Protocol.eq("any"))
            .add(firewall_rule::Column::Protocol.is_null())
    } else {
        Condition::all().add(firewall_rule::Column::Protocol.eq(protocol))
    }
}
