#[cfg(target_os = "linux")]
pub(in crate::data_plane::xdp) use crate::policy::model::{
    CompiledPolicy, XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix,
    XdpPrefixRule, XdpTempBan, XdpTrustedPrefix,
};
#[cfg(target_os = "linux")]
use std::net::IpAddr;

mod attach;
mod dispatcher;
#[cfg(target_os = "linux")]
mod encoding;
#[cfg(any(target_os = "linux", test))]
mod local;
mod manager;
#[cfg(any(target_os = "linux", test))]
mod maps;
mod types;

pub use attach::resolve_interface_name;
pub use dispatcher::{
    dispatcher_replace, dispatcher_status, dispatcher_temp_bans, dispatcher_unload,
    drop_config_pin_path, drop_events_pin_path, existing_xdp_summary, map_pin_dir,
};
#[cfg(target_os = "linux")]
pub(in crate::data_plane::xdp) use encoding::*;
#[cfg(any(target_os = "linux", test))]
pub(in crate::data_plane::xdp) use local::*;
pub use manager::XdpManager;
#[cfg(target_os = "linux")]
pub(in crate::data_plane::xdp) use maps::{resized_map_sizes, usize_to_u32, validate_map_capacity};
pub use types::*;

#[cfg(target_os = "linux")]
pub(in crate::data_plane::xdp) type Result<T> = anyhow::Result<T>;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(test)]
mod tests;
