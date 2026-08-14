use super::super::parse_node_interface_ips;
use crate::{control_plane::security, db::entities::node, policy::node_maintenance};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(in crate::control_plane::api) struct NodeResponse {
    node_id: String,
    interface_name: String,
    interface_ips: Vec<String>,
    last_seen_at: chrono::NaiveDateTime,
    last_applied_version: i64,
    current_policy_version: i64,
    status: String,
    sync_status: String,
    healthy: bool,
    seconds_since_seen: i64,
    error: Option<String>,
}

impl NodeResponse {
    pub(super) fn new(
        value: node::Model,
        current_policy_version: i64,
        now: chrono::NaiveDateTime,
    ) -> Self {
        let seconds_since_seen = node_maintenance::seconds_since_seen(value.last_seen_at, now);
        let sync_status = node_maintenance::sync_status(
            &value.status,
            value.last_applied_version,
            current_policy_version,
            value.last_seen_at,
            now,
            node_maintenance::DEFAULT_UNHEALTHY_NODE_AFTER_SECONDS,
        );
        let healthy = sync_status == "ok";
        Self {
            node_id: value.node_id,
            interface_name: value.interface_name,
            interface_ips: parse_node_interface_ips(&value.interface_ips)
                .unwrap_or_default()
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
            last_seen_at: value.last_seen_at,
            last_applied_version: value.last_applied_version,
            current_policy_version,
            status: value.status,
            sync_status,
            healthy,
            seconds_since_seen,
            error: value.error.as_deref().map(security::public_error_message),
        }
    }
}
