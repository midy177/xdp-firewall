use crate::data_plane::xdp::{
    self, DEFAULT_COUNTRY_MAP_ENTRIES, DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES,
    DEFAULT_GEO_MAP_ENTRIES, DEFAULT_RATE_MAP_ENTRIES, DEFAULT_RULE_MAP_ENTRIES,
    DEFAULT_TEMP_BAN_MAP_ENTRIES, DEFAULT_TRUSTED_MAP_ENTRIES,
};
use clap::Args;

#[derive(Debug, Args, Clone)]
pub struct XdpMapCapacityArgs {
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

impl XdpMapCapacityArgs {
    pub(crate) fn xdp_map_sizes(&self) -> xdp::XdpMapSizes {
        xdp::XdpMapSizes {
            rule_entries: self.rule_map_entries,
            geo_entries: self.geo_map_entries,
            trusted_entries: self.trusted_map_entries,
            country_entries: self.country_map_entries,
            rate_entries: self.rate_map_entries,
            custom_rate_limit_entries: self.custom_rate_limit_map_entries,
            temp_ban_entries: self.temp_ban_map_entries,
        }
    }
}
