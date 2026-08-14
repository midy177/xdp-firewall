use super::*;

impl ThreatSourceRefresh {
    pub(in crate::control_plane::xds) fn new(
        interval: Duration,
        threat_lookup: threat::ThreatIntelLookup,
    ) -> Self {
        Self {
            state: Arc::new(StdMutex::new(TimedRefreshState::new_successful(
                Instant::now(),
            ))),
            interval,
            threat_lookup,
        }
    }

    pub(in crate::control_plane::xds) async fn maybe_run(
        &self,
        db: &DatabaseConnection,
    ) -> Result<()> {
        let started_at = Instant::now();
        let gate = self.gate(started_at);
        if let Some(skip) = refresh_skip_without_missing(gate) {
            log_threat_refresh_skip(skip, self.interval);
            return Ok(());
        }
        let missing_states = if gate.within_interval {
            threat::enabled_threat_source_states_missing(db).await?
        } else {
            false
        };
        if let Some(skip) = refresh_skip_with_missing(gate, missing_states) {
            log_threat_refresh_skip(skip, self.interval);
            return Ok(());
        }

        if let Some(skip) = self.try_start(started_at, missing_states) {
            log_threat_refresh_skip(skip, self.interval);
            return Ok(());
        }

        info!(
            missing_states,
            refresh_interval_seconds = self.interval.as_secs(),
            "starting threat intelligence background refresh"
        );
        let result = threat::refresh_enabled_threat_sources(db).await;
        match result {
            Ok(report) => self.finish_success(db, started_at, report).await,
            Err(err) => {
                self.state
                    .lock()
                    .expect("threat source refresh mutex poisoned")
                    .running = false;
                warn!(error = %err, "threat intelligence refresh failed during xDS push tick");
                Err(err)
            }
        }
    }

    async fn finish_success(
        &self,
        db: &DatabaseConnection,
        started_at: Instant,
        report: threat::ThreatRefreshReport,
    ) -> Result<()> {
        if report.running {
            self.state
                .lock()
                .expect("threat source refresh mutex poisoned")
                .finish();
            info!(
                status = %report.refresh_status,
                "threat intelligence refresh is already running elsewhere; skipping automatic xDS refresh"
            );
            return Ok(());
        }

        {
            let mut state = self
                .state
                .lock()
                .expect("threat source refresh mutex poisoned");
            state.finish_success(started_at);
        }
        if report.refreshed {
            let version = latest_version(db).await?;
            self.threat_lookup.spawn_rebuild(db.clone());
            info!(
                enabled_threat_sources = report.enabled_source_count,
                changed_threat_sources = report.changed_source_count,
                prefixes = report.prefix_count,
                version,
                "refreshed threat intelligence sources during xDS push tick"
            );
        } else {
            info!(
                status = %report.refresh_status,
                enabled_threat_sources = report.enabled_source_count,
                prefixes = report.prefix_count,
                "completed threat intelligence background refresh without changes"
            );
        }
        Ok(())
    }

    fn gate(&self, started_at: Instant) -> RefreshGate {
        let state = self
            .state
            .lock()
            .expect("threat source refresh mutex poisoned");
        state.gate(started_at, self.interval, THREAT_REFRESH_RETRY_INTERVAL)
    }

    fn try_start(&self, started_at: Instant, missing_states: bool) -> Option<RefreshSkip> {
        let mut state = self
            .state
            .lock()
            .expect("threat source refresh mutex poisoned");
        state.try_start(
            started_at,
            self.interval,
            THREAT_REFRESH_RETRY_INTERVAL,
            missing_states,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::entities::threat_source_state, policy::model::DEFAULT_POLICY_NAME};
    use sea_orm::{ActiveModelTrait, ConnectOptions, Database, Set};

    #[tokio::test]
    async fn running_report_does_not_mark_refresh_successful() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        let now = chrono::Utc::now().naive_utc();
        threat_source_state::ActiveModel {
            policy_name: Set("__threat_refresh_lock__".to_string()),
            source_name: Set(DEFAULT_POLICY_NAME.to_string()),
            fingerprint: Set("running:test-owner".to_string()),
            prefix_count: Set(0),
            last_checked_at: Set(now),
            last_changed_at: Set(Some(now)),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let previous_success = Instant::now() - Duration::from_secs(120);
        let refresh = ThreatSourceRefresh {
            state: Arc::new(StdMutex::new(TimedRefreshState {
                last_success: Some(previous_success),
                last_attempt: None,
                running: false,
            })),
            interval: Duration::from_secs(60),
            threat_lookup: threat::ThreatIntelLookup::default(),
        };

        refresh.maybe_run(&db).await.unwrap();

        let state = refresh
            .state
            .lock()
            .expect("threat source refresh mutex poisoned");
        assert!(!state.running);
        assert_eq!(state.last_success, Some(previous_success));
        assert!(state.last_attempt.is_some());
    }
}
