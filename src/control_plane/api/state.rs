use super::xds;
use crate::intelligence::{geo, threat};
use sea_orm::DatabaseConnection;
use std::{
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(super) struct ApiState {
    pub(super) db: DatabaseConnection,
    pub(super) api_token: Option<String>,
    pub(super) drop_events: xds::DropEventHub,
    pub(super) geo_lookup: geo::GeoIpLookup,
    pub(super) geo_refresh_limiter: GeoRefreshLimiter,
    pub(super) threat_refresh_limiter: ThreatRefreshLimiter,
    pub(super) standby: bool,
}

#[derive(Clone)]
pub(super) struct RefreshLimiter<T> {
    state: Arc<StdMutex<RefreshLimiterState<T>>>,
}

pub(super) struct RefreshLimiterState<T> {
    last_started: Option<Instant>,
    running: bool,
    last_result: Option<T>,
}

pub(super) struct RefreshPermit<T> {
    limiter: RefreshLimiter<T>,
}

#[derive(Clone)]
pub(super) struct CachedGeoRefresh {
    pub(super) version: i64,
    pub(super) report: geo::GeoRefreshReport,
}

#[derive(Clone)]
pub(super) struct CachedThreatRefresh {
    pub(super) version: i64,
    pub(super) report: threat::ThreatRefreshReport,
}

pub(super) enum RefreshDecision<T> {
    Start {
        permit: RefreshPermit<T>,
        previous: Option<T>,
    },
    Running(Option<T>),
    RateLimited(Option<T>),
}

pub(super) type GeoRefreshLimiter = RefreshLimiter<CachedGeoRefresh>;
pub(super) type GeoRefreshDecision = RefreshDecision<CachedGeoRefresh>;
pub(super) type ThreatRefreshLimiter = RefreshLimiter<CachedThreatRefresh>;
pub(super) type ThreatRefreshDecision = RefreshDecision<CachedThreatRefresh>;

impl<T: Clone> RefreshLimiter<T> {
    pub(super) fn start_or_cached(&self, interval: Duration) -> RefreshDecision<T> {
        let now = Instant::now();
        let mut state = self.state.lock().expect("refresh limiter mutex poisoned");
        if state.running {
            return RefreshDecision::Running(state.last_result.clone());
        }
        if let Some(last_started) = state.last_started {
            let elapsed = now.saturating_duration_since(last_started);
            if elapsed < interval {
                return RefreshDecision::RateLimited(state.last_result.clone());
            }
        }
        state.running = true;
        state.last_started = Some(now);
        RefreshDecision::Start {
            permit: RefreshPermit {
                limiter: self.clone(),
            },
            previous: state.last_result.clone(),
        }
    }
}

impl<T> Default for RefreshLimiter<T> {
    fn default() -> Self {
        Self {
            state: Arc::new(StdMutex::new(RefreshLimiterState::default())),
        }
    }
}

impl<T> Default for RefreshLimiterState<T> {
    fn default() -> Self {
        Self {
            last_started: None,
            running: false,
            last_result: None,
        }
    }
}

impl<T> RefreshPermit<T> {
    pub(super) fn finish_success(&self, result: T) {
        let mut state = self
            .limiter
            .state
            .lock()
            .expect("refresh limiter mutex poisoned");
        state.last_result = Some(result);
    }
}

impl<T> Drop for RefreshPermit<T> {
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .expect("refresh limiter mutex poisoned");
        state.running = false;
    }
}
