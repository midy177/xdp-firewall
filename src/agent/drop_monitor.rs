use crate::{cli::AgentArgs, data_plane::xdp};
use tracing::{debug, error, info, warn};

mod reporter;

use reporter::spawn_reporter;

pub(super) type DropMonitorHandle = Option<tokio::task::JoinHandle<()>>;

pub(super) fn reconcile(
    xdp: &mut xdp::XdpManager,
    handle: &mut DropMonitorHandle,
    enabled: bool,
    args: &AgentArgs,
    node_id: &str,
    interface: &str,
) {
    if enabled && handle.is_none() {
        enable(xdp, handle, args, node_id, interface);
    } else if !enabled {
        disable(xdp, handle);
    }
}

pub(super) fn disable(xdp: &mut xdp::XdpManager, handle: &mut DropMonitorHandle) {
    if let Some(task) = handle.take() {
        task.abort();
        if let Err(err) = xdp.set_drop_monitor_enabled(false) {
            warn!(
                error = %err,
                "failed to disable XDP drop monitor; enforcement continues"
            );
        }
        info!("disabled xDS drop monitor reporting");
    }
}

pub(super) fn log_xdp_stats(xdp: &xdp::XdpManager) {
    match xdp.stats() {
        Ok(stats) => {
            debug!(
                pass = stats.pass,
                drop_total = stats.total_drop(),
                rule_drop = stats.rule_drop,
                geo_drop = stats.geo_drop,
                rate_drop = stats.rate_drop,
                flood_drop = stats.flood_drop,
                custom_rate_drop = stats.custom_rate_drop,
                temp_ban_drop = stats.temp_ban_drop,
                parse_drop = stats.parse_drop,
                "xdp stats"
            );
        }
        Err(err) => {
            error!(error = %err, "failed to read xdp stats");
        }
    }
}

fn enable(
    xdp: &mut xdp::XdpManager,
    handle: &mut DropMonitorHandle,
    args: &AgentArgs,
    node_id: &str,
    interface: &str,
) {
    if let Some(events_path) = enable_xdp_drop_monitor(xdp, interface) {
        *handle = Some(spawn_reporter(args, node_id, interface, events_path));
        info!("enabled xDS drop monitor reporting");
    }
}

fn enable_xdp_drop_monitor(
    xdp: &mut xdp::XdpManager,
    interface: &str,
) -> Option<std::path::PathBuf> {
    if let Err(err) = xdp.set_drop_monitor_enabled(true) {
        warn!(
            error = %err,
            "failed to enable XDP drop monitor; enforcement continues without drop event reporting"
        );
        return None;
    }
    match xdp::drop_events_pin_path(interface) {
        Ok(path) => Some(path),
        Err(err) => {
            warn!(
                error = %err,
                "failed to resolve XDP drop event pin path; enforcement continues without drop event reporting"
            );
            None
        }
    }
}
