use super::{
    DropEventHub, build_policy_update, internal_status,
    proto::{PolicyUpdate, StreamPolicyRequest},
    refresh::TempBanCleanup,
    runtime_cidrs::RuntimeTrustedCidrs,
};
use sea_orm::DatabaseConnection;
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::Status;
use tracing::{info, warn};

mod drop_monitor;

use drop_monitor::{send_drop_monitor_change, send_drop_monitor_update};

type PolicyStreamSender = mpsc::Sender<std::result::Result<PolicyUpdate, Status>>;

pub(super) struct PolicyStreamTask {
    pub(super) db: DatabaseConnection,
    pub(super) interval: Duration,
    pub(super) drop_events: DropEventHub,
    pub(super) runtime_trusted_cidrs: RuntimeTrustedCidrs,
    pub(super) temp_ban_cleanup: TempBanCleanup,
    pub(super) request: StreamPolicyRequest,
    pub(super) tx: PolicyStreamSender,
}

struct PolicyStreamCursor {
    version: i64,
    runtime_fingerprint: Option<String>,
    drop_monitor_enabled: bool,
}

impl PolicyStreamCursor {
    fn new(task: &PolicyStreamTask) -> Self {
        Self {
            version: task.request.current_version,
            runtime_fingerprint: None,
            drop_monitor_enabled: task.drop_events.enabled_for_node(&task.request.node_id),
        }
    }
}

pub(super) fn spawn_policy_stream_task(task: PolicyStreamTask) {
    tokio::spawn(async move {
        run_policy_stream(task).await;
    });
}

async fn run_policy_stream(task: PolicyStreamTask) {
    let mut drop_monitor_changes = task.drop_events.subscribe_changes();
    let mut cursor = PolicyStreamCursor::new(&task);
    if cursor.drop_monitor_enabled && !send_drop_monitor_update(&task, &cursor) {
        return;
    }

    loop {
        if task.tx.is_closed() || !send_available_policy_update(&task, &mut cursor).await {
            break;
        }
        tokio::select! {
            () = task.tx.closed() => break,
            changed = drop_monitor_changes.changed() => {
                if changed.is_err() || !send_drop_monitor_change(&task, &mut cursor) {
                    break;
                }
            }
            () = tokio::time::sleep(task.interval) => {}
        }
    }
}

async fn send_available_policy_update(
    task: &PolicyStreamTask,
    cursor: &mut PolicyStreamCursor,
) -> bool {
    let update = build_policy_update(
        &task.db,
        cursor.version,
        cursor.runtime_fingerprint.as_deref(),
        &task.runtime_trusted_cidrs,
        &task.temp_ban_cleanup,
        task.request.supports_external_geo_prefixes,
    )
    .await;

    match update {
        Ok(Some((mut update, runtime_fingerprint))) => {
            update.drop_monitor_enabled = task.drop_events.enabled_for_node(&task.request.node_id);
            if !send_policy_update(task, &update, &runtime_fingerprint) {
                return false;
            }
            cursor.version = update.version;
            cursor.runtime_fingerprint = Some(runtime_fingerprint);
            cursor.drop_monitor_enabled = update.drop_monitor_enabled;
            true
        }
        Ok(None) => true,
        Err(err) => {
            let _ = task.tx.try_send(Err(internal_status(err)));
            false
        }
    }
}

fn send_policy_update(
    task: &PolicyStreamTask,
    update: &PolicyUpdate,
    runtime_fingerprint: &str,
) -> bool {
    match task.tx.try_send(Ok(update.clone())) {
        Ok(()) => {
            info!(
                node_id = %task.request.node_id,
                interface = %task.request.interface_name,
                version = update.version,
                runtime_fingerprint,
                "xDS pushed updated policy"
            );
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(
                node_id = %task.request.node_id,
                interface = %task.request.interface_name,
                "xDS policy stream client is not draining updates; closing stream"
            );
            false
        }
    }
}
