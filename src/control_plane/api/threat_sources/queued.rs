use super::refresh_task::run_threat_refresh;
use sea_orm::DatabaseConnection;
use std::time::Duration;
use tracing::{info, warn};

const QUEUED_THREAT_REFRESH_RETRY_DELAY: Duration = Duration::from_secs(5);
const QUEUED_THREAT_REFRESH_MAX_ATTEMPTS: usize = 12;

pub(in crate::control_plane::api) fn spawn_threat_refresh(db: DatabaseConnection) {
    tokio::spawn(async move {
        for attempt in 1..=QUEUED_THREAT_REFRESH_MAX_ATTEMPTS {
            match run_threat_refresh(db.clone()).await {
                Ok(result) if result.report.running => {
                    if attempt == QUEUED_THREAT_REFRESH_MAX_ATTEMPTS {
                        warn!(
                            attempts = attempt,
                            "queued threat intelligence refresh is still running elsewhere"
                        );
                        break;
                    }
                    tokio::time::sleep(QUEUED_THREAT_REFRESH_RETRY_DELAY).await;
                }
                Ok(result) => {
                    info!(
                        version = result.version,
                        enabled_threat_sources = result.report.enabled_source_count,
                        changed_threat_sources = result.report.changed_source_count,
                        prefixes = result.report.prefix_count,
                        attempts = attempt,
                        "queued threat intelligence refresh completed"
                    );
                    break;
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        attempts = attempt,
                        "queued threat intelligence refresh failed"
                    );
                    break;
                }
            }
        }
    });
}
