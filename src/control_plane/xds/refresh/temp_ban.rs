use super::super::cleanup_expired_temp_bans;
use anyhow::Result;
use sea_orm::DatabaseConnection;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::info;

#[derive(Clone)]
pub(in crate::control_plane::xds) struct TempBanCleanup {
    state: Arc<Mutex<TempBanCleanupState>>,
    interval: Duration,
    standby: bool,
}

#[derive(Default)]
struct TempBanCleanupState {
    last_success: Option<Instant>,
    running: bool,
}

impl TempBanCleanup {
    pub(in crate::control_plane::xds) fn new(interval: Duration, standby: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(TempBanCleanupState::default())),
            interval,
            standby,
        }
    }

    pub(in crate::control_plane::xds) async fn maybe_run(
        &self,
        db: &DatabaseConnection,
    ) -> Result<()> {
        if self.standby {
            return Ok(());
        }
        let started_at = Instant::now();
        if !self.try_start(started_at).await {
            return Ok(());
        }

        let result = cleanup_expired_temp_bans(db).await;
        self.finish(started_at, result.is_ok()).await;

        let (deleted, version) = result?;
        if let Some(version) = version {
            info!(
                deleted_expired_temp_bans = deleted,
                version, "cleaned up expired temporary bans during xDS push tick"
            );
        }
        Ok(())
    }

    async fn try_start(&self, started_at: Instant) -> bool {
        let mut state = self.state.lock().await;
        if state.running || self.within_interval(&state, started_at) {
            return false;
        }
        state.running = true;
        true
    }

    fn within_interval(&self, state: &TempBanCleanupState, started_at: Instant) -> bool {
        state
            .last_success
            .and_then(|last| started_at.checked_duration_since(last))
            .is_some_and(|elapsed| elapsed < self.interval)
    }

    async fn finish(&self, started_at: Instant, succeeded: bool) {
        let mut state = self.state.lock().await;
        state.running = false;
        if succeeded {
            state.last_success = Some(started_at);
        }
    }
}
