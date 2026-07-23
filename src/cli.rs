use clap::{Args, Parser, Subcommand};

use crate::xdp::{
    DEFAULT_COUNTRY_MAP_ENTRIES, DEFAULT_GEO_MAP_ENTRIES, DEFAULT_RATE_MAP_ENTRIES,
    DEFAULT_RULE_MAP_ENTRIES, DEFAULT_TRUSTED_MAP_ENTRIES, XdpAttachMode,
};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "sqlite://xdp-firewall.db?mode=rwc",
        help = "SQLite, PostgreSQL, or MySQL URL, for example sqlite://xdp-firewall.db?mode=rwc, postgres://..., or mysql://..."
    )]
    pub database_url: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Migrate,
    Api(ApiArgs),
    Agent(AgentArgs),
    SyncOnce(SyncOnceArgs),
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Args, Clone)]
pub struct ApiArgs {
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: String,
    #[arg(
        long = "trusted-cidr",
        alias = "trusted-cidrs",
        env = "XDP_FIREWALL_TRUSTED_CIDRS",
        value_delimiter = ',',
        help = "Trusted source CIDR allowlist for global ip_rate_limit and flood. Can be repeated or comma-separated. These prefixes are persisted to the policy database."
    )]
    pub trusted_cidrs: Vec<String>,
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
    #[arg(long, default_value_t = 5)]
    pub poll_seconds: u64,
    #[arg(long, default_value_t = 30)]
    pub heartbeat_seconds: u64,
    #[arg(long, default_value = "xdp_firewall")]
    pub program: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_RULE_MAP_ENTRIES",
        default_value_t = DEFAULT_RULE_MAP_ENTRIES
    )]
    pub rule_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_GEO_MAP_ENTRIES",
        default_value_t = DEFAULT_GEO_MAP_ENTRIES
    )]
    pub geo_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_TRUSTED_MAP_ENTRIES",
        default_value_t = DEFAULT_TRUSTED_MAP_ENTRIES
    )]
    pub trusted_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_COUNTRY_MAP_ENTRIES",
        default_value_t = DEFAULT_COUNTRY_MAP_ENTRIES
    )]
    pub country_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_RATE_MAP_ENTRIES",
        default_value_t = DEFAULT_RATE_MAP_ENTRIES
    )]
    pub rate_map_entries: u32,
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
        default_value_t = DEFAULT_RULE_MAP_ENTRIES
    )]
    pub rule_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_GEO_MAP_ENTRIES",
        default_value_t = DEFAULT_GEO_MAP_ENTRIES
    )]
    pub geo_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_TRUSTED_MAP_ENTRIES",
        default_value_t = DEFAULT_TRUSTED_MAP_ENTRIES
    )]
    pub trusted_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_COUNTRY_MAP_ENTRIES",
        default_value_t = DEFAULT_COUNTRY_MAP_ENTRIES
    )]
    pub country_map_entries: u32,
    #[arg(
        long,
        env = "XDP_FIREWALL_RATE_MAP_ENTRIES",
        default_value_t = DEFAULT_RATE_MAP_ENTRIES
    )]
    pub rate_map_entries: u32,
}

#[derive(Debug, Args, Clone)]
pub struct SeedExampleArgs {}

#[derive(Debug, Args, Clone)]
pub struct ShowPolicyArgs {}
