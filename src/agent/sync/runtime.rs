use crate::agent::{config, drop_monitor, offline};
use crate::cli::AgentArgs;
use crate::{control_plane::xds, data_plane::xdp, policy::model::DEFAULT_POLICY_NAME};
use anyhow::Result;
use std::net::IpAddr;
use tokio::time::Duration;
use tracing::info;

use config::{format_interface_ips, resolve_node_id};
use offline::OfflinePolicyState;

mod connect;
mod heartbeat;
mod offline_handling;
mod stream;

pub(super) async fn run(args: AgentArgs) -> Result<()> {
    AgentRuntime::attach(args)?.run().await
}

struct AgentRuntime {
    args: AgentArgs,
    node_id: String,
    interface: String,
    interface_ips: Vec<IpAddr>,
    xdp: xdp::XdpManager,
    applied_version: i64,
    heartbeat_interval: Duration,
    reconnect_delay: Duration,
    drop_monitor: drop_monitor::DropMonitorHandle,
    offline: OfflinePolicyState,
}

enum AgentStreamOutcome {
    Reconnect,
    Shutdown,
}

enum StreamMessageOutcome {
    Continue,
    Reconnect,
}

impl AgentRuntime {
    fn attach(args: AgentArgs) -> Result<Self> {
        let node_id = resolve_node_id(args.node_id.as_deref())?;
        let policy = DEFAULT_POLICY_NAME;
        info!(
            node_id = %node_id,
            policy,
            control_url = %args.control_url,
            configured_interface = ?args.interface,
            xdp_mode = %args.xdp.xdp_mode.as_str(),
            xdp_attach_strategy = %args.xdp.xdp_attach_strategy.as_str(),
            xdp_allow_replace = args.xdp.xdp_allow_replace,
            xdp_run_priority = args.xdp_run_priority,
            xdp_object = %args.xdp.xdp_object,
            program = %args.xdp.program,
            heartbeat_seconds = args.heartbeat_seconds,
            offline_mode = %args.offline_mode.as_str(),
            offline_failure_limit = args.offline_failure_limit,
            rule_map_entries = args.xdp.map_capacities.rule_map_entries,
            geo_map_entries = args.xdp.map_capacities.geo_map_entries,
            trusted_map_entries = args.xdp.map_capacities.trusted_map_entries,
            country_map_entries = args.xdp.map_capacities.country_map_entries,
            rate_map_entries = args.xdp.map_capacities.rate_map_entries,
            custom_rate_limit_map_entries = args.xdp.map_capacities.custom_rate_limit_map_entries,
            temp_ban_map_entries = args.xdp.map_capacities.temp_ban_map_entries,
            "attaching XDP for agent"
        );
        let xdp = xdp::XdpManager::attach(
            args.interface.as_deref(),
            &args.xdp.xdp_object,
            &args.xdp.program,
            args.xdp.map_sizes(),
            args.xdp.attach_options(args.xdp_run_priority),
        )?;
        let interface = xdp.interface_name().to_string();
        let interface_ips = xdp.interface_ips();
        info!(
            node_id = %node_id,
            policy,
            interface = %interface,
            interface_ips = %format_interface_ips(&interface_ips),
            "agent attached XDP"
        );
        let heartbeat_interval = Duration::from_secs(args.heartbeat_seconds);
        let reconnect_delay = heartbeat_interval.min(Duration::from_secs(10));
        Ok(Self {
            args,
            node_id,
            interface,
            interface_ips,
            xdp,
            applied_version: -1,
            heartbeat_interval,
            reconnect_delay,
            drop_monitor: None,
            offline: OfflinePolicyState::default(),
        })
    }

    async fn run(mut self) -> Result<()> {
        loop {
            let Some((mut client, mut stream)) = self.connect_and_subscribe().await? else {
                continue;
            };
            match self.run_policy_stream(&mut client, &mut stream).await? {
                AgentStreamOutcome::Reconnect => {}
                AgentStreamOutcome::Shutdown => return Ok(()),
            }
        }
    }
}
