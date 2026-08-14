use super::{GEO_IP_REFRESH_RETRY_INTERVAL, THREAT_REFRESH_RETRY_INTERVAL};
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone, Copy)]
pub(super) struct RefreshGate {
    pub(super) running: bool,
    pub(super) retry_throttled: bool,
    pub(super) within_interval: bool,
}

#[derive(Clone, Copy)]
pub(super) enum RefreshSkip {
    Running,
    RetryThrottled,
    WithinInterval,
}

pub(super) fn refresh_gate(
    running: bool,
    last_success: Option<Instant>,
    last_attempt: Option<Instant>,
    started_at: Instant,
    interval: Duration,
    retry_interval: Duration,
) -> RefreshGate {
    RefreshGate {
        running,
        retry_throttled: elapsed_less_than(last_attempt, started_at, retry_interval),
        within_interval: elapsed_less_than(last_success, started_at, interval),
    }
}

fn elapsed_less_than(last: Option<Instant>, now: Instant, interval: Duration) -> bool {
    last.and_then(|last| now.checked_duration_since(last))
        .is_some_and(|elapsed| elapsed < interval)
}

pub(super) fn refresh_skip_without_missing(gate: RefreshGate) -> Option<RefreshSkip> {
    if gate.running {
        return Some(RefreshSkip::Running);
    }
    if gate.retry_throttled {
        return Some(RefreshSkip::RetryThrottled);
    }
    None
}

pub(super) fn refresh_skip_with_missing(
    gate: RefreshGate,
    missing_data: bool,
) -> Option<RefreshSkip> {
    refresh_skip_without_missing(gate)
        .or_else(|| (gate.within_interval && !missing_data).then_some(RefreshSkip::WithinInterval))
}

pub(super) fn log_geo_refresh_skip(skip: RefreshSkip, interval: Duration) {
    match skip {
        RefreshSkip::Running => {
            info!("skipping country IP background refresh because a refresh is already running");
        }
        RefreshSkip::RetryThrottled => {
            info!(
                retry_interval_seconds = GEO_IP_REFRESH_RETRY_INTERVAL.as_secs(),
                "skipping country IP background refresh because the retry interval has not elapsed"
            );
        }
        RefreshSkip::WithinInterval => {
            info!(
                refresh_interval_seconds = interval.as_secs(),
                "skipping country IP background refresh because the refresh interval has not elapsed"
            );
        }
    }
}

pub(super) fn log_threat_refresh_skip(skip: RefreshSkip, interval: Duration) {
    match skip {
        RefreshSkip::Running => {
            info!(
                "skipping threat intelligence background refresh because a refresh is already running"
            );
        }
        RefreshSkip::RetryThrottled => {
            info!(
                retry_interval_seconds = THREAT_REFRESH_RETRY_INTERVAL.as_secs(),
                "skipping threat intelligence background refresh because the retry interval has not elapsed"
            );
        }
        RefreshSkip::WithinInterval => {
            info!(
                refresh_interval_seconds = interval.as_secs(),
                "skipping threat intelligence background refresh because the refresh interval has not elapsed"
            );
        }
    }
}
