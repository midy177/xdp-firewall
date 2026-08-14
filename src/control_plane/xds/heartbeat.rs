use super::proto::HeartbeatRequest;
use crate::{control_plane::security, db::entities::node, policy::model::DEFAULT_POLICY_NAME};
use anyhow::{Context, Result};
use sea_orm::{DatabaseConnection, EntityTrait, Set, sea_query::OnConflict};
use std::net::IpAddr;

pub(super) async fn upsert_heartbeat(
    db: &DatabaseConnection,
    request: HeartbeatRequest,
) -> Result<()> {
    node::Entity::insert(heartbeat_model(request)?)
        .on_conflict(heartbeat_conflict_update())
        .exec_without_returning(db)
        .await?;
    Ok(())
}

fn heartbeat_model(request: HeartbeatRequest) -> Result<node::ActiveModel> {
    let public_error = public_heartbeat_error(&request.error);
    Ok(node::ActiveModel {
        node_id: Set(request.node_id),
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        interface_name: Set(request.interface_name),
        interface_ips: Set(normalize_heartbeat_interface_ips(request.interface_ips)?),
        last_seen_at: Set(chrono::Utc::now().naive_utc()),
        last_applied_version: Set(request.last_applied_version),
        status: Set(request.status),
        error: Set(public_error),
    })
}

fn public_heartbeat_error(error: &str) -> Option<String> {
    (!error.trim().is_empty()).then(|| security::public_error_message(error))
}

fn heartbeat_conflict_update() -> sea_orm::sea_query::OnConflict {
    OnConflict::column(node::Column::NodeId)
        .update_columns([
            node::Column::PolicyName,
            node::Column::InterfaceName,
            node::Column::InterfaceIps,
            node::Column::LastSeenAt,
            node::Column::LastAppliedVersion,
            node::Column::Status,
            node::Column::Error,
        ])
        .to_owned()
}

fn normalize_heartbeat_interface_ips(values: Vec<String>) -> Result<String> {
    let mut ips = values
        .into_iter()
        .flat_map(split_heartbeat_interface_ips)
        .map(parse_heartbeat_ip)
        .collect::<Result<Vec<_>>>()?;
    ips.sort();
    ips.dedup();
    Ok(ips
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(","))
}

fn split_heartbeat_interface_ips(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_heartbeat_ip(value: String) -> Result<IpAddr> {
    value
        .parse()
        .with_context(|| format!("invalid heartbeat interface IP '{value}'"))
}
