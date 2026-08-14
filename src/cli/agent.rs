use clap::Args;

mod monitor;
mod sync_once;
mod xdp;

pub use monitor::MonitorArgs;
pub use sync_once::SyncOnceArgs;
pub use xdp::AgentXdpArgs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AgentOfflineMode {
    UnloadRules,
    KeepRules,
}

impl AgentOfflineMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnloadRules => "unload-rules",
            Self::KeepRules => "keep-rules",
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct AgentArgs {
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
        help = "gRPC xDS control-plane URL used by the agent."
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
        default_value_t = 0,
        help = "Dispatcher run priority. Lower values run earlier in the libxdp dispatcher chain."
    )]
    pub xdp_run_priority: i32,
    #[arg(long, default_value_t = 30)]
    pub heartbeat_seconds: u64,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_OFFLINE_MODE",
        value_enum,
        default_value_t = AgentOfflineMode::UnloadRules,
        help = "Agent offline behavior after consecutive xDS/API connection failures: unload-rules clears XDP policy maps, keep-rules keeps the last applied policy."
    )]
    pub offline_mode: AgentOfflineMode,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_OFFLINE_FAILURE_LIMIT",
        default_value_t = 5,
        help = "Consecutive xDS/API connection failures before offline-mode unload-rules clears XDP firewall rules."
    )]
    pub offline_failure_limit: u32,
    #[command(flatten)]
    pub xdp: AgentXdpArgs,
}
