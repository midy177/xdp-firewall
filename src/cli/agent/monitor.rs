use clap::Args;

#[derive(Debug, Args, Clone)]
pub struct MonitorArgs {
    #[arg(
        long,
        env = "XDP_FIREWALL_NODE_ID",
        help = "Node identity used when querying xDS. Uses XDP_FIREWALL_NODE_ID, NODE_ID, HOSTNAME, or /etc/hostname when omitted."
    )]
    pub node_id: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_URL",
        default_value = "http://127.0.0.1:50051",
        help = "gRPC xDS control-plane URL used by monitor."
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
        help = "Network interface to inspect. Auto-detects the default-route interface when omitted."
    )]
    pub interface: Option<String>,
    #[arg(long, default_value_t = 5)]
    pub interval_seconds: u64,
    #[arg(long, help = "Print one monitor sample and exit.")]
    pub once: bool,
    #[arg(long, help = "Print monitor samples as JSON lines.")]
    pub json: bool,
    #[arg(
        long,
        help = "Stream realtime XDP drop events from the pinned agent map."
    )]
    pub r#drop: bool,
    #[arg(
        long,
        env = "XDP_FIREWALL_DROP_EVENTS_PATH",
        help = "Pinned drop_events map path. Defaults to /sys/fs/bpf/xdp-firewall/<interface>/drop_events."
    )]
    pub drop_events_path: Option<String>,
}
