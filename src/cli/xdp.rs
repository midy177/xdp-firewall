use clap::{Args, Subcommand};

use crate::{cli::XdpMapCapacityArgs, data_plane::xdp::XdpAttachMode};

#[derive(Debug, Subcommand)]
pub enum XdpCommand {
    Status(XdpStatusArgs),
    TempBans(XdpTempBansArgs),
    Unload(XdpUnloadArgs),
    Replace(XdpReplaceArgs),
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
pub struct XdpTempBansArgs {
    #[arg(
        long,
        help = "Network interface whose pinned temp_bans map should be listed. Auto-detects the default-route interface when omitted."
    )]
    pub interface: Option<String>,
    #[arg(long, help = "Print JSON instead of a text table.")]
    pub json: bool,
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
        env = "XDP_FIREWALL_BPFTOOL_PATH",
        default_value = "bpftool",
        hide = true
    )]
    pub bpftool_path: String,
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
    #[command(flatten)]
    pub map_capacities: XdpMapCapacityArgs,
}
