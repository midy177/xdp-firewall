use clap::Args;

use crate::{
    cli::XdpMapCapacityArgs,
    data_plane::xdp::{XdpAttachMode, XdpAttachOptions, XdpAttachStrategy, XdpMapSizes},
};

#[derive(Debug, Args, Clone)]
pub struct AgentXdpArgs {
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
    #[arg(long, default_value = "/usr/local/share/xdp-firewall/xdp_firewall.o")]
    pub xdp_object: String,
    #[arg(long, default_value = "xdp_firewall")]
    pub program: String,
    #[command(flatten)]
    pub map_capacities: XdpMapCapacityArgs,
    #[arg(
        long,
        env = "XDP_FIREWALL_AUTO_RESIZE_MAPS",
        hide = true,
        default_value_t = true
    )]
    pub auto_resize_maps: bool,
}

impl AgentXdpArgs {
    #[must_use]
    pub fn map_sizes(&self) -> XdpMapSizes {
        self.map_capacities.xdp_map_sizes()
    }

    #[must_use]
    pub fn attach_options(&self, run_priority: i32) -> XdpAttachOptions {
        XdpAttachOptions {
            mode: self.xdp_mode,
            strategy: self.xdp_attach_strategy,
            allow_replace: self.xdp_allow_replace,
            auto_resize_maps: self.auto_resize_maps,
            run_priority,
            loader_path: self.xdp_loader_path.clone(),
            bpftool_path: self.bpftool_path.clone(),
        }
    }
}
