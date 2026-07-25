use clap::{Args, Parser, Subcommand};

use crate::xdp::{
    DEFAULT_COUNTRY_MAP_ENTRIES, DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES, DEFAULT_GEO_MAP_ENTRIES,
    DEFAULT_RATE_MAP_ENTRIES, DEFAULT_RULE_MAP_ENTRIES, DEFAULT_TEMP_BAN_MAP_ENTRIES,
    DEFAULT_TRUSTED_MAP_ENTRIES, XdpAttachMode, XdpAttachStrategy,
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
    Xdp {
        #[command(subcommand)]
        command: XdpCommand,
    },
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

#[derive(Debug, Subcommand)]
pub enum XdpCommand {
    Status(XdpStatusArgs),
    Unload(XdpUnloadArgs),
    Replace(XdpReplaceArgs),
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
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_ATTACH_STRATEGY",
        value_enum,
        default_value_t = XdpAttachStrategy::Direct,
        help = "XDP attach strategy: direct uses Aya's native attach path; dispatcher uses xdp-loader/libxdp multiprogram attach and pinned maps."
    )]
    pub xdp_attach_strategy: XdpAttachStrategy,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_ALLOW_REPLACE",
        default_value_t = false,
        help = "Allow direct attach to proceed when an XDP program is already present on the interface. Leave false to avoid replacing another XDP user such as Cilium or Katran."
    )]
    pub xdp_allow_replace: bool,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_RUN_PRIORITY",
        default_value_t = 10,
        help = "Dispatcher run priority. Lower values run earlier in the libxdp dispatcher chain."
    )]
    pub xdp_run_priority: i32,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_LOADER_PATH",
        default_value = "xdp-loader",
        hide = true
    )]
    pub xdp_loader_path: String,
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
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_ATTACH_STRATEGY",
        value_enum,
        default_value_t = XdpAttachStrategy::Direct,
        help = "XDP attach strategy: direct uses Aya's native attach path; dispatcher uses xdp-loader/libxdp multiprogram attach and pinned maps."
    )]
    pub xdp_attach_strategy: XdpAttachStrategy,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_ALLOW_REPLACE",
        default_value_t = false,
        help = "Allow direct attach to proceed when an XDP program is already present on the interface."
    )]
    pub xdp_allow_replace: bool,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_RUN_PRIORITY",
        default_value_t = 10,
        help = "Dispatcher run priority. Lower values run earlier in the libxdp dispatcher chain."
    )]
    pub xdp_run_priority: i32,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_LOADER_PATH",
        default_value = "xdp-loader",
        hide = true
    )]
    pub xdp_loader_path: String,
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
pub struct XdpStatusArgs {
    #[arg(
        long,
        help = "Network interface to inspect. Auto-detects the default-route interface when omitted."
    )]
    pub interface: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_LOADER_PATH",
        default_value = "xdp-loader",
        hide = true
    )]
    pub xdp_loader_path: String,
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Args, Clone)]
pub struct XdpUnloadArgs {
    #[arg(
        long,
        help = "Network interface to unload from. Required for destructive dispatcher operations."
    )]
    pub interface: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_LOADER_PATH",
        default_value = "xdp-loader",
        hide = true
    )]
    pub xdp_loader_path: String,
    #[arg(
        long,
        conflicts_with = "all",
        help = "Unload one dispatcher program ID."
    )]
    pub id: Option<u32>,
    #[arg(
        long,
        help = "Unload all dispatcher programs and the dispatcher from the interface."
    )]
    pub all: bool,
    #[arg(
        long,
        help = "After unloading all dispatcher programs, remove /sys/fs/bpf/xdp-firewall/<interface> pinned maps."
    )]
    pub remove_pins: bool,
    #[arg(
        long,
        help = "Run xdp-loader clean for detached dispatcher links after unload."
    )]
    pub clean: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Args, Clone)]
pub struct XdpReplaceArgs {
    #[arg(
        long,
        help = "Network interface to replace on. Required for destructive dispatcher operations."
    )]
    pub interface: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_LOADER_PATH",
        default_value = "xdp-loader",
        hide = true
    )]
    pub xdp_loader_path: String,
    #[arg(
        long,
        conflicts_with = "all",
        help = "Optionally unload one dispatcher program ID before loading the replacement."
    )]
    pub id: Option<u32>,
    #[arg(
        long,
        help = "Optionally unload all dispatcher programs and the dispatcher before loading the replacement."
    )]
    pub all: bool,
    #[arg(
        long,
        help = "Remove /sys/fs/bpf/xdp-firewall/<interface> pinned maps before loading the replacement. This starts with empty maps."
    )]
    pub remove_pins: bool,
    #[arg(
        long,
        help = "Run xdp-loader clean for detached dispatcher links after unloading the old program."
    )]
    pub clean: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_MODE",
        value_enum,
        default_value_t = XdpAttachMode::Auto,
        help = "Replacement dispatcher attach mode: auto tries native first and falls back to skb; driver requires native; skb uses generic XDP."
    )]
    pub xdp_mode: XdpAttachMode,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDP_RUN_PRIORITY",
        default_value_t = 10,
        help = "Dispatcher run priority for the replacement. Lower values run earlier."
    )]
    pub xdp_run_priority: i32,
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
pub struct SeedExampleArgs {}

#[derive(Debug, Args, Clone)]
pub struct ShowPolicyArgs {}
