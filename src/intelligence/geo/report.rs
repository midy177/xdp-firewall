use serde::Serialize;

use super::IPDENY_ROOT;

#[derive(Debug, Clone, Serialize)]
pub struct GeoRefreshReport {
    pub countries: Vec<String>,
    pub checked_country_count: usize,
    pub changed_country_count: usize,
    pub unchanged_country_count: usize,
    pub failed_country_count: usize,
    pub prefix_count: usize,
    pub provider_base_url: &'static str,
    pub refresh_status: String,
    pub cached: bool,
    pub running: bool,
    pub errors: Vec<String>,
}

impl GeoRefreshReport {
    pub fn empty(refresh_status: impl Into<String>) -> Self {
        Self {
            countries: Vec::new(),
            checked_country_count: 0,
            changed_country_count: 0,
            unchanged_country_count: 0,
            failed_country_count: 0,
            prefix_count: 0,
            provider_base_url: IPDENY_ROOT,
            refresh_status: refresh_status.into(),
            cached: false,
            running: false,
            errors: Vec::new(),
        }
    }

    #[must_use]
    pub fn running() -> Self {
        let mut report = Self::empty("running");
        report.running = true;
        report
    }
}
