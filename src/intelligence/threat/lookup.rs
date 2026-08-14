use anyhow::Result;
use sea_orm::DatabaseConnection;
use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Instant,
};
use tracing::warn;

use self::{
    database::{ThreatIntelDatabase, open_threat_intel_database},
    db::{current_policy_version, load_threat_sources_by_cidr},
    mmdb::{ThreatIntelDatabaseFile, build_threat_intel_database_file},
    state::ThreatIntelLookupState,
};
use super::THREAT_LOOKUP_VERSION_CHECK_INTERVAL;

mod database;
mod db;
mod mmdb;
mod state;

#[derive(Clone, Default)]
pub struct ThreatIntelLookup {
    state: Arc<RwLock<ThreatIntelLookupState>>,
}

impl ThreatIntelLookup {
    pub async fn lookup_source(&self, db: &DatabaseConnection, ip: IpAddr) -> Option<String> {
        let now = Instant::now();
        let should_check_version = {
            let state = self
                .state
                .read()
                .expect("threat intel lookup lock poisoned");
            state.should_check_version(now, THREAT_LOOKUP_VERSION_CHECK_INTERVAL)
        };
        if should_check_version && let Ok(version) = current_policy_version(db).await {
            self.queue_rebuild_for_version(db.clone(), version, Some(now));
        }

        let state = self
            .state
            .read()
            .expect("threat intel lookup lock poisoned");
        state.lookup_source(ip)
    }

    pub fn spawn_rebuild(&self, db: DatabaseConnection) {
        let started = {
            let mut state = self
                .state
                .write()
                .expect("threat intel lookup lock poisoned");
            state.start_forced_rebuild()
        };
        if !started {
            return;
        }
        let lookup = self.clone();
        tokio::spawn(async move {
            let result = async {
                let version = current_policy_version(&db).await?;
                lookup.rebuild_from_db(&db, version).await
            }
            .await;
            lookup.finish_background_rebuild(result);
        });
    }

    fn queue_rebuild_for_version(
        &self,
        db: DatabaseConnection,
        version: i64,
        checked_at: Option<Instant>,
    ) {
        let should_spawn = {
            let mut state = self
                .state
                .write()
                .expect("threat intel lookup lock poisoned");
            state.start_rebuild_for_version(version, checked_at)
        };
        if !should_spawn {
            return;
        }
        let lookup = self.clone();
        tokio::spawn(async move {
            let result = lookup.rebuild_from_db(&db, version).await;
            lookup.finish_background_rebuild(result);
        });
    }

    fn finish_background_rebuild(&self, result: Result<usize>) {
        let mut state = self
            .state
            .write()
            .expect("threat intel lookup lock poisoned");
        state.finish_rebuild();
        if let Err(err) = result {
            warn!(error = %err, "failed to rebuild threat intelligence lookup database");
        }
    }

    pub async fn rebuild_from_db(&self, db: &DatabaseConnection, version: i64) -> Result<usize> {
        let sources_by_cidr = load_threat_sources_by_cidr(db).await?;
        if sources_by_cidr.is_empty() {
            self.clear_database_for_version(version);
            return Ok(0);
        }

        let file = build_threat_intel_database_file(sources_by_cidr)?;
        let count = file.prefix_count;
        self.install_database_for_version(version, file)?;
        Ok(count)
    }

    fn install_database_for_version(
        &self,
        version: i64,
        file: ThreatIntelDatabaseFile,
    ) -> Result<()> {
        let database = open_threat_intel_database(file)?;
        let mut state = self
            .state
            .write()
            .expect("threat intel lookup lock poisoned");
        state.install_database(version, database);
        Ok(())
    }

    fn clear_database_for_version(&self, version: i64) {
        let mut state = self
            .state
            .write()
            .expect("threat intel lookup lock poisoned");
        state.clear_database(version);
    }
}
