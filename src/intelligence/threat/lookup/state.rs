use super::ThreatIntelDatabase;
use std::{net::IpAddr, time::Duration, time::Instant};

#[derive(Default)]
pub(super) struct ThreatIntelLookupState {
    version: Option<i64>,
    last_checked: Option<Instant>,
    rebuild_running: bool,
    database: Option<ThreatIntelDatabase>,
}

impl ThreatIntelLookupState {
    pub(super) fn should_check_version(&self, now: Instant, interval: Duration) -> bool {
        self.last_checked
            .is_none_or(|last| now.saturating_duration_since(last) >= interval)
    }

    pub(super) fn lookup_source(&self, ip: IpAddr) -> Option<String> {
        self.database.as_ref()?.lookup_source(ip)
    }

    pub(super) fn start_forced_rebuild(&mut self) -> bool {
        if self.rebuild_running {
            return false;
        }
        self.rebuild_running = true;
        self.database = None;
        true
    }

    pub(super) fn start_rebuild_for_version(
        &mut self,
        version: i64,
        checked_at: Option<Instant>,
    ) -> bool {
        if let Some(checked_at) = checked_at {
            self.last_checked = Some(checked_at);
        }
        if self.version == Some(version) || self.rebuild_running {
            return false;
        }
        self.rebuild_running = true;
        self.database = None;
        true
    }

    pub(super) fn finish_rebuild(&mut self) {
        self.rebuild_running = false;
    }

    pub(super) fn install_database(&mut self, version: i64, database: ThreatIntelDatabase) {
        self.version = Some(version);
        self.database = Some(database);
    }

    pub(super) fn clear_database(&mut self, version: i64) {
        self.version = Some(version);
        self.database = None;
    }
}
