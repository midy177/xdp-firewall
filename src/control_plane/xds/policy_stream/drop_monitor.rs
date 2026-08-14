use super::super::proto::PolicyUpdate;
use super::{PolicyStreamCursor, PolicyStreamTask};
use tokio::sync::mpsc;
use tracing::{info, warn};

pub(super) fn send_drop_monitor_change(
    task: &PolicyStreamTask,
    cursor: &mut PolicyStreamCursor,
) -> bool {
    let enabled = task.drop_events.enabled_for_node(&task.request.node_id);
    if enabled == cursor.drop_monitor_enabled {
        return true;
    }
    cursor.drop_monitor_enabled = enabled;
    send_drop_monitor_update(task, cursor)
}

pub(super) fn send_drop_monitor_update(
    task: &PolicyStreamTask,
    cursor: &PolicyStreamCursor,
) -> bool {
    let update = PolicyUpdate {
        version: cursor.version.max(0),
        policy_json: String::new(),
        drop_monitor_enabled: cursor.drop_monitor_enabled,
        external_geo_prefixes: false,
        geo_prefix_version: 0,
    };
    match task.tx.try_send(Ok(update)) {
        Ok(()) => {
            info!(
                node_id = %task.request.node_id,
                interface = %task.request.interface_name,
                drop_monitor_enabled = cursor.drop_monitor_enabled,
                "xDS pushed drop monitor setting"
            );
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(
                node_id = %task.request.node_id,
                interface = %task.request.interface_name,
                "xDS policy stream client is not draining monitor updates; closing stream"
            );
            false
        }
    }
}
