use super::{config, policy_apply};
use crate::cli::{AgentArgs, SyncOnceArgs};
use crate::{control_plane::xds, data_plane::xdp, policy::model::DEFAULT_POLICY_NAME};
use anyhow::{Result, bail};
use tracing::info;

use config::{resolve_node_id, sync_once_status, validate_positive_arg};

mod runtime;

#[cfg(test)]
mod tests;

pub async fn sync_once(args: SyncOnceArgs) -> Result<()> {
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
        "attaching XDP for sync-once"
    );
    let mut xdp = xdp::XdpManager::attach(
        args.interface.as_deref(),
        &args.xdp.xdp_object,
        &args.xdp.program,
        args.xdp.map_sizes(),
        args.xdp.attach_options(args.xdp_run_priority),
    )?;
    let interface = xdp.interface_name().to_string();
    let interface_ips = xdp.interface_ips();
    let mut client = xds::XdsClient::connect(xds::XdsClientConfig {
        control_url: args.control_url.clone(),
        agent_token: args.agent_token.clone(),
    })
    .await?;
    let Some((version, snapshot)) = client.fetch_policy(&node_id, &interface, -1).await? else {
        bail!("xDS control plane returned unchanged policy for initial sync");
    };
    let applied = policy_apply::apply_latest(&mut xdp, snapshot, &args.control_url, version)?;
    let (status, error) = sync_once_status();
    client
        .report_heartbeat(
            &node_id,
            &interface,
            &interface_ips,
            applied,
            status,
            error.as_deref(),
        )
        .await?;
    info!(
        node_id = %node_id,
        policy,
        interface = %interface,
        xds_version = version,
        version = applied,
        "policy synced once"
    );
    Ok(())
}

pub async fn run_agent(args: AgentArgs) -> Result<()> {
    validate_positive_arg("heartbeat-seconds", args.heartbeat_seconds)?;
    validate_positive_arg(
        "offline-failure-limit",
        u64::from(args.offline_failure_limit),
    )?;
    runtime::run(args).await
}
