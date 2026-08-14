use super::{
    GEO_IP_REFRESH_RETRY_INTERVAL, THREAT_REFRESH_RETRY_INTERVAL, geo_ip_lists_missing,
    latest_version,
};
use crate::intelligence::{geo, threat};
use anyhow::Result;
use sea_orm::DatabaseConnection;
use std::{
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tracing::{info, warn};

mod gate;
mod geo_ip;
mod temp_ban;
mod threat_source;

use gate::{
    RefreshGate, RefreshSkip, log_geo_refresh_skip, log_threat_refresh_skip, refresh_gate,
    refresh_skip_with_missing, refresh_skip_without_missing,
};
pub(super) use temp_ban::TempBanCleanup;

#[derive(Clone)]
pub(super) struct GeoIpRefresh {
    state: Arc<StdMutex<TimedRefreshState>>,
    interval: Duration,
    geo_lookup: geo::GeoIpLookup,
}

#[derive(Default)]
struct TimedRefreshState {
    last_success: Option<Instant>,
    last_attempt: Option<Instant>,
    running: bool,
}

#[derive(Clone)]
pub(super) struct ThreatSourceRefresh {
    state: Arc<StdMutex<TimedRefreshState>>,
    interval: Duration,
    threat_lookup: threat::ThreatIntelLookup,
}

impl TimedRefreshState {
    fn new_successful(now: Instant) -> Self {
        Self {
            last_success: Some(now),
            ..Default::default()
        }
    }

    fn gate(
        &self,
        started_at: Instant,
        interval: Duration,
        retry_interval: Duration,
    ) -> RefreshGate {
        refresh_gate(
            self.running,
            self.last_success,
            self.last_attempt,
            started_at,
            interval,
            retry_interval,
        )
    }

    fn try_start(
        &mut self,
        started_at: Instant,
        interval: Duration,
        retry_interval: Duration,
        missing_resources: bool,
    ) -> Option<RefreshSkip> {
        let gate = self.gate(started_at, interval, retry_interval);
        if let Some(skip) = refresh_skip_with_missing(gate, missing_resources) {
            return Some(skip);
        }
        self.running = true;
        self.last_attempt = Some(started_at);
        None
    }

    fn finish(&mut self) {
        self.running = false;
    }

    fn finish_success(&mut self, started_at: Instant) {
        self.running = false;
        self.last_success = Some(started_at);
    }
}
