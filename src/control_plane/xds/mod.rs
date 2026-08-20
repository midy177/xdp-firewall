use crate::{
    control_plane::k8s,
    intelligence::{geo, threat},
};
use sea_orm::DatabaseConnection;
use std::time::Duration;
use tonic::Status;

const TEMP_BAN_CLEANUP_INTERVAL: Duration = Duration::from_mins(1);
const AUTO_REFRESH_INTERVAL: Duration = Duration::from_hours(24);
const GEO_IP_REFRESH_RETRY_INTERVAL: Duration = Duration::from_mins(5);
const THREAT_REFRESH_RETRY_INTERVAL: Duration = Duration::from_mins(5);
const THREAT_MISSING_PREFIX_POLL_INTERVAL: Duration = Duration::from_mins(30);
const XDS_MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;
const K8S_WATCH_TIMEOUT: Duration = Duration::from_mins(5);
const K8S_WATCH_RECONNECT_DELAY: Duration = Duration::from_secs(5);
const K8S_WATCH_CHANGE_DEBOUNCE: Duration = Duration::from_secs(1);

#[allow(
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
pub mod proto {
    tonic::include_proto!("xdp_firewall.xds.v1");
}

mod auth;
mod client;
mod drop_events;
mod fetch;
mod heartbeat;
mod policy_stream;
mod refresh;
mod runtime_cidrs;
mod server;
mod service;
mod state;
mod tls;

pub use client::{PolicyUpdateError, XdsClient, XdsClientConfig, XdsClientTls};
pub use drop_events::{DropEventHub, DropEventSubscription, DropEventView};
use refresh::TempBanCleanup;
use runtime_cidrs::RuntimeTrustedCidrs;
pub use server::serve;
use state::{build_policy_update, cleanup_expired_temp_bans, geo_ip_lists_missing, latest_version};
pub use tls::{ControlPlaneTls, build_control_plane_tls};

const GEO_PREFIX_PAGE_SIZE: u32 = 4096;

#[derive(Clone)]
struct XdsService {
    db: DatabaseConnection,
    agent_token: Option<String>,
    push_interval: Duration,
    drop_events: DropEventHub,
    runtime_trusted_cidrs: RuntimeTrustedCidrs,
    temp_ban_cleanup: TempBanCleanup,
    geo_lookup: geo::GeoIpLookup,
    threat_lookup: threat::ThreatIntelLookup,
    standby: bool,
}

fn internal_status(error: impl std::fmt::Display) -> Status {
    Status::internal(error.to_string())
}

#[cfg(test)]
mod tests;
