use super::{
    ThreatPrefix, ThreatRefreshReport, ThreatSource,
    lock::ThreatRefreshDbLock,
    source_fetch::{fetch_threat_source_prefixes, normalize_prefixes, threat_http_client},
};
use anyhow::Result;
use sea_orm::DatabaseConnection;

mod batch;
mod persistence;
mod state;

use batch::refresh_threat_source_batch;
use persistence::persist_threat_refresh_batch;
use state::{
    load_enabled_threat_sources, load_existing_threat_prefix_sources, load_existing_threat_states,
};

impl ThreatRefreshReport {
    pub fn empty(refresh_status: impl Into<String>) -> Self {
        Self {
            enabled_source_count: 0,
            changed_source_count: 0,
            prefix_count: 0,
            refreshed: false,
            refresh_status: refresh_status.into(),
            cached: false,
            running: false,
        }
    }
}

pub async fn fetch_threat_prefixes(sources: &[ThreatSource]) -> Result<Vec<ThreatPrefix>> {
    let mut prefixes = Vec::new();
    let client = threat_http_client()?;
    for source in sources {
        prefixes.extend(fetch_threat_source_prefixes(&client, source).await?);
    }
    Ok(normalize_prefixes(prefixes))
}

pub async fn refresh_enabled_threat_sources(
    db: &DatabaseConnection,
) -> Result<ThreatRefreshReport> {
    let Some(_guard) = ThreatRefreshDbLock::try_acquire(db).await? else {
        return Ok(ThreatRefreshReport {
            running: true,
            ..ThreatRefreshReport::empty("running")
        });
    };
    let sources = load_enabled_threat_sources(db).await?;
    let enabled_source_count = sources.len() as u64;
    if enabled_source_count == 0 {
        return Ok(ThreatRefreshReport {
            enabled_source_count,
            ..ThreatRefreshReport::empty("empty")
        });
    }

    let existing = load_existing_threat_states(db).await?;
    let existing_prefix_sources = load_existing_threat_prefix_sources(db).await?;
    let client = threat_http_client()?;
    let now = chrono::Utc::now().naive_utc();
    let batch =
        refresh_threat_source_batch(&client, &sources, &existing, &existing_prefix_sources, now)
            .await?;
    let changed_source_count = batch.changed_source_count;
    let prefix_count = batch.prefix_count;
    persist_threat_refresh_batch(db, batch).await?;

    Ok(threat_refresh_report(
        enabled_source_count,
        changed_source_count,
        prefix_count,
    ))
}

fn threat_refresh_report(
    enabled_source_count: u64,
    changed_source_count: u64,
    prefix_count: usize,
) -> ThreatRefreshReport {
    ThreatRefreshReport {
        enabled_source_count,
        changed_source_count,
        prefix_count,
        refreshed: changed_source_count > 0,
        refresh_status: if changed_source_count > 0 {
            "changed".to_string()
        } else {
            "unchanged".to_string()
        },
        cached: false,
        running: false,
    }
}
