use super::*;

impl GeoIpRefresh {
    pub(in crate::control_plane::xds) fn new(
        interval: Duration,
        geo_lookup: geo::GeoIpLookup,
    ) -> Self {
        Self {
            state: Arc::new(StdMutex::new(TimedRefreshState::new_successful(
                Instant::now(),
            ))),
            interval,
            geo_lookup,
        }
    }

    pub(in crate::control_plane::xds) async fn maybe_run(
        &self,
        db: &DatabaseConnection,
    ) -> Result<()> {
        let started_at = Instant::now();
        let gate = self.gate(started_at);
        if let Some(skip) = refresh_skip_without_missing(gate) {
            log_geo_refresh_skip(skip, self.interval);
            return Ok(());
        }
        let missing_lists = if gate.within_interval {
            geo_ip_lists_missing(db).await?
        } else {
            false
        };
        if let Some(skip) = refresh_skip_with_missing(gate, missing_lists) {
            log_geo_refresh_skip(skip, self.interval);
            return Ok(());
        }

        if let Some(skip) = self.try_start(started_at, missing_lists) {
            log_geo_refresh_skip(skip, self.interval);
            return Ok(());
        }

        info!(
            missing_lists,
            refresh_interval_seconds = self.interval.as_secs(),
            "starting country IP background refresh"
        );
        self.spawn_refresh_task(db.clone(), started_at);
        Ok(())
    }

    fn gate(&self, started_at: Instant) -> RefreshGate {
        let state = self.state.lock().expect("geo IP refresh mutex poisoned");
        state.gate(started_at, self.interval, GEO_IP_REFRESH_RETRY_INTERVAL)
    }

    fn try_start(&self, started_at: Instant, missing_lists: bool) -> Option<RefreshSkip> {
        let mut state = self.state.lock().expect("geo IP refresh mutex poisoned");
        state.try_start(
            started_at,
            self.interval,
            GEO_IP_REFRESH_RETRY_INTERVAL,
            missing_lists,
        )
    }

    fn spawn_refresh_task(&self, db: DatabaseConnection, started_at: Instant) {
        let state = self.state.clone();
        let geo_lookup = self.geo_lookup.clone();
        tokio::spawn(async move {
            let result = run_geo_refresh(&db, &geo_lookup).await;
            finish_geo_refresh(&state, started_at, result);
        });
    }
}

async fn run_geo_refresh(
    db: &DatabaseConnection,
    geo_lookup: &geo::GeoIpLookup,
) -> Result<geo::GeoRefreshReport> {
    let report = geo::refresh_all_ipdeny_lists(db).await?;
    if report.changed_country_count > 0 {
        log_changed_geo_refresh(db, geo_lookup, &report).await?;
    } else {
        log_unchanged_geo_refresh(&report);
    }
    Ok(report)
}

async fn log_changed_geo_refresh(
    db: &DatabaseConnection,
    geo_lookup: &geo::GeoIpLookup,
    report: &geo::GeoRefreshReport,
) -> Result<()> {
    let lookup_prefixes = geo_lookup.rebuild_from_db(db).await?;
    let version = latest_version(db).await?;
    info!(
        checked_countries = report.checked_country_count,
        changed_countries = report.changed_country_count,
        prefixes = report.prefix_count,
        lookup_prefixes,
        version,
        "refreshed changed country IP lists during xDS push tick"
    );
    Ok(())
}

fn log_unchanged_geo_refresh(report: &geo::GeoRefreshReport) {
    info!(
        status = %report.refresh_status,
        checked_countries = report.checked_country_count,
        changed_countries = report.changed_country_count,
        failed_countries = report.failed_country_count,
        prefixes = report.prefix_count,
        "completed country IP background refresh without changes"
    );
}

fn finish_geo_refresh(
    state: &StdMutex<TimedRefreshState>,
    started_at: Instant,
    result: Result<geo::GeoRefreshReport>,
) {
    let mut guard = state.lock().expect("geo IP refresh mutex poisoned");
    guard.finish();
    match result {
        Ok(report) if report.failed_country_count == 0 && !report.running => {
            guard.finish_success(started_at);
        }
        Ok(report) if report.running => {
            info!(
                status = %report.refresh_status,
                "country IP refresh is already running elsewhere; skipping automatic xDS refresh"
            );
        }
        Ok(report) => {
            warn!(
                status = %report.refresh_status,
                failed_countries = report.failed_country_count,
                "country IP refresh did not complete cleanly during xDS push tick"
            );
        }
        Err(err) => {
            warn!(error = %err, "country IP refresh failed during xDS push tick");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_report_does_not_mark_refresh_successful() {
        let previous_success = Instant::now() - Duration::from_secs(120);
        let state = StdMutex::new(TimedRefreshState {
            last_success: Some(previous_success),
            last_attempt: Some(previous_success),
            running: true,
        });

        finish_geo_refresh(&state, Instant::now(), Ok(geo::GeoRefreshReport::running()));

        let state = state.lock().expect("geo IP refresh mutex poisoned");
        assert!(!state.running);
        assert_eq!(state.last_success, Some(previous_success));
    }
}
