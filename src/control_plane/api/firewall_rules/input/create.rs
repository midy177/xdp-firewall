use super::{normalize_rule_key, rule_insert_error};
use crate::control_plane::api::{
    ApiError, ApiResult, normalize_action, normalize_cidr, normalize_protocol,
    parse_normalized_cidr, validate_port,
};
use crate::{db::entities::firewall_rule, policy::model::DEFAULT_POLICY_NAME};
use ipnet::IpNet;
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct CreateRuleRequest {
    pub(super) rule_key: Option<String>,
    pub(super) enabled: Option<bool>,
    pub(super) priority: i32,
    pub(super) action: String,
    pub(super) cidr: String,
    pub(super) protocol: Option<String>,
    pub(super) port: Option<i32>,
    pub(super) comment: Option<String>,
}

pub(in crate::control_plane::api) struct RuleInput {
    rule_key: String,
    enabled: bool,
    priority: i32,
    action: String,
    cidr: String,
    protocol: Option<String>,
    port: Option<i32>,
    comment: Option<String>,
}

pub(in crate::control_plane::api) struct RuleCreate {
    pub(in crate::control_plane::api) row: firewall_rule::Model,
    pub(in crate::control_plane::api) inserted: bool,
}

pub(in crate::control_plane::api) fn rule_input(
    request: CreateRuleRequest,
) -> ApiResult<RuleInput> {
    let rule_key = normalize_rule_key(request.rule_key)?;
    let cidr = normalize_cidr(&request.cidr)?;
    let protocol = request
        .protocol
        .as_deref()
        .map(normalize_protocol)
        .transpose()?;
    let port = validate_port(protocol.as_deref(), request.port)?;
    let action = normalize_action(&request.action)?;
    let rule_key = rule_key.unwrap_or_else(|| {
        firewall_rule::generated_rule_key(
            request.priority,
            &action,
            &cidr,
            protocol.as_deref(),
            port,
        )
    });
    Ok(RuleInput {
        rule_key,
        enabled: request.enabled.unwrap_or(true),
        priority: request.priority,
        action,
        cidr,
        protocol,
        port,
        comment: request.comment,
    })
}

pub(in crate::control_plane::api) async fn create_rule<C>(
    db: &C,
    input: RuleInput,
) -> ApiResult<RuleCreate>
where
    C: ConnectionTrait,
{
    let existing = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(firewall_rule::Column::RuleKey.eq(&input.rule_key))
        .one(db)
        .await?;
    let Some(existing) = existing else {
        let row = input
            .active_model()
            .insert(db)
            .await
            .map_err(rule_insert_error)?;
        return Ok(RuleCreate {
            row,
            inserted: true,
        });
    };
    if input.matches_existing(&existing) {
        return Ok(RuleCreate {
            row: existing,
            inserted: false,
        });
    }
    Err(ApiError::conflict("firewall rule_key already exists"))
}

impl RuleInput {
    fn active_model(self) -> firewall_rule::ActiveModel {
        firewall_rule::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            rule_key: Set(self.rule_key),
            enabled: Set(self.enabled),
            priority: Set(self.priority),
            action: Set(self.action),
            cidr: Set(self.cidr),
            protocol: Set(self.protocol),
            port: Set(self.port),
            comment: Set(self.comment),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
    }

    fn matches_existing(&self, row: &firewall_rule::Model) -> bool {
        row.enabled == self.enabled
            && row.priority == self.priority
            && row.action == self.action
            && row.cidr == self.cidr
            && row.protocol == self.protocol
            && row.port == self.port
            && row.comment == self.comment
    }
}

pub(in crate::control_plane::api) fn deny_rule_cidr(
    request: &CreateRuleRequest,
) -> ApiResult<Option<IpNet>> {
    let action = normalize_action(&request.action)?;
    if action != "deny" {
        return Ok(None);
    }
    Ok(Some(parse_normalized_cidr(&request.cidr)?))
}
