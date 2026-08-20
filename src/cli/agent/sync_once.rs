use clap::Args;

use super::{AgentXdpArgs, XdsTlsClientArgs};

#[derive(Debug, Args, Clone)]
pub struct SyncOnceArgs {
    #[arg(
        long,
        env = "XDP_FIREWALL_NODE_ID",
        help = "Node identity for heartbeats. Uses XDP_FIREWALL_NODE_ID, NODE_ID, HOSTNAME, or /etc/hostname when omitted."
    )]
    pub node_id: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_URL",
        default_value = "http://127.0.0.1:50051",
        help = "gRPC xDS control-plane URL used by sync-once."
    )]
    pub control_url: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_TOKEN",
        help = "Bearer token sent to the xDS control plane."
    )]
    pub agent_token: Option<String>,
    #[arg(
        long,
        help = "Network interface to attach XDP to. Auto-detects the default-route interface when omitted."
    )]
    pub interface: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_RUN_PRIORITY",
        default_value_t = 10,
        help = "Dispatcher run priority. Lower values run earlier in the libxdp dispatcher chain."
    )]
    pub xdp_run_priority: i32,
    #[command(flatten)]
    pub xdp: AgentXdpArgs,
    #[command(flatten)]
    pub xds_tls: XdsTlsClientArgs,
}
