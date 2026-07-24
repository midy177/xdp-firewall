use clap::{Args, Parser, Subcommand};

use crate::xdp::{
    DEFAULT_COUNTRY_MAP_ENTRIES, DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES, DEFAULT_GEO_MAP_ENTRIES,
    DEFAULT_RATE_MAP_ENTRIES, DEFAULT_RULE_MAP_ENTRIES, DEFAULT_TEMP_BAN_MAP_ENTRIES,
    DEFAULT_TRUSTED_MAP_ENTRIES, XdpAttachMode,
};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Migrate(DatabaseArgs),
    Api(ApiArgs),
    Xds(XdsArgs),
    Agent(AgentArgs),
    SyncOnce(SyncOnceArgs),
    Monitor(MonitorArgs),
    Policy {
        #[command(flatten)]
        database: DatabaseArgs,
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Args, Clone)]
pub struct DatabaseArgs {
    #[arg(
        long,
        env = "DATABASE_URL",
        help = "SQLite, PostgreSQL, or MySQL URL required by control-plane database commands, for example sqlite://xdp-firewall.db?mode=rwc, postgres://..., or mysql://..."
    )]
    pub database_url: String,
}

#[derive(Debug, Args, Clone)]
pub struct ApiArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    #[command(flatten)]
    pub k8s: K8sDiscoveryArgs,
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_BIND",
        default_value = "0.0.0.0:50051",
        help = "gRPC xDS bind address exposed by the API control-plane process."
    )]
    pub xds_bind: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_PUSH_INTERVAL_SECONDS",
        default_value_t = 5,
        help = "Minimum xDS policy push interval in seconds. The control plane checks for changed policy versions at this cadence."
    )]
    pub xds_push_interval_seconds: u64,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_TOKEN",
        help = "Bearer token required from XDP agents. Required when xDS binds to a non-loopback address."
    )]
    pub agent_token: Option<String>,
    #[arg(
        long = "trusted-cidr",
        alias = "trusted-cidrs",
        env = "XDP_FIREWALL_TRUSTED_CIDRS",
        value_delimiter = ',',
        help = "Runtime-only highest-priority source CIDR whitelist injected into xDS snapshots. Can be repeated or comma-separated. These prefixes are not persisted to the policy database."
    )]
    pub trusted_cidrs: Vec<String>,
}

#[derive(Debug, Args, Clone)]
pub struct XdsArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    #[command(flatten)]
    pub k8s: K8sDiscoveryArgs,
    #[arg(long, default_value = "0.0.0.0:50051")]
    pub bind: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_PUSH_INTERVAL_SECONDS",
        default_value_t = 5,
        help = "Minimum xDS policy push interval in seconds. The control plane checks for changed policy versions at this cadence."
    )]
    pub push_interval_seconds: u64,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_TOKEN",
        help = "Bearer token required from XDP agents. Required when xDS binds to a non-loopback address."
    )]
    pub agent_token: Option<String>,
    #[arg(
        long = "trusted-cidr",
        alias = "trusted-cidrs",
        env = "XDP_FIREWALL_TRUSTED_CIDRS",
        value_delimiter = ',',
        help = "Runtime-only highest-priority source CIDR whitelist injected into xDS snapshots. Can be repeated or comma-separated. These prefixes are not persisted to the policy database."
    )]
    pub trusted_cidrs: Vec<String>,
}

#[derive(Debug, Args, Clone)]
pub struct K8sDiscoveryArgs {
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_DISCOVERY",
        default_value_t = false,
        help = "Enable Kubernetes runtime address discovery in the control plane. Discovered node IPs, Pod CIDRs, and Service CIDRs are injected into xDS snapshots as runtime-only whitelist entries and are not persisted."
    )]
    pub k8s_discovery: bool,
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_API_SERVER",
        help = "Kubernetes API server URL. Defaults to https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS or KUBERNETES_SERVICE_PORT}."
    )]
    pub k8s_api_server: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_TOKEN_PATH",
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/token",
        help = "Kubernetes service account bearer token path used by control-plane discovery."
    )]
    pub k8s_token_path: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_CA_CERT_PATH",
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        help = "Kubernetes service account CA certificate path used by control-plane discovery."
    )]
    pub k8s_ca_cert_path: String,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    SeedExample(SeedExampleArgs),
    Show(ShowPolicyArgs),
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
        env = "XDP_FIREWALL_XDP_MODE",
        value_enum,
        default_value_t = XdpAttachMode::Auto,
        help = "XDP attach mode: auto tries driver mode first and falls back to skb; driver fails if native XDP is unavailable; skb skips native XDP."
    )]
    pub xdp_mode: XdpAttachMode,
    #[arg(long, default_value = "/usr/local/share/xdp-firewall/xdp_firewall.o")]
    pub xdp_object: String,
    #[arg(long, default_value_t = 30)]
    pub heartbeat_seconds: u64,
    #[arg(long, default_value = "xdp_firewall")]
    pub program: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_RULE_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_RULE_MAP_ENTRIES
    )]
    pub rule_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_GEO_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_GEO_MAP_ENTRIES
    )]
    pub geo_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_TRUSTED_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_TRUSTED_MAP_ENTRIES
    )]
    pub trusted_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_COUNTRY_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_COUNTRY_MAP_ENTRIES
    )]
    pub country_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_RATE_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_RATE_MAP_ENTRIES
    )]
    pub rate_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_CUSTOM_RATE_LIMIT_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES
    )]
    pub custom_rate_limit_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_TEMP_BAN_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_TEMP_BAN_MAP_ENTRIES
    )]
    pub temp_ban_map_entries: u32,
}

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
        env = "XDP_FIREWALL_XDP_MODE",
        value_enum,
        default_value_t = XdpAttachMode::Auto,
        help = "XDP attach mode: auto tries driver mode first and falls back to skb; driver fails if native XDP is unavailable; skb skips native XDP."
    )]
    pub xdp_mode: XdpAttachMode,
    #[arg(long, default_value = "/usr/local/share/xdp-firewall/xdp_firewall.o")]
    pub xdp_object: String,
    #[arg(long, default_value = "xdp_firewall")]
    pub program: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_RULE_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_RULE_MAP_ENTRIES
    )]
    pub rule_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_GEO_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_GEO_MAP_ENTRIES
    )]
    pub geo_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_TRUSTED_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_TRUSTED_MAP_ENTRIES
    )]
    pub trusted_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_COUNTRY_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_COUNTRY_MAP_ENTRIES
    )]
    pub country_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_RATE_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_RATE_MAP_ENTRIES
    )]
    pub rate_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_CUSTOM_RATE_LIMIT_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES
    )]
    pub custom_rate_limit_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_TEMP_BAN_MAP_ENTRIES",
        hide = true,
        default_value_t = DEFAULT_TEMP_BAN_MAP_ENTRIES
    )]
    pub temp_ban_map_entries: u32,
}

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

#[derive(Debug, Args, Clone)]
pub struct SeedExampleArgs {}

#[derive(Debug, Args, Clone)]
pub struct ShowPolicyArgs {}
