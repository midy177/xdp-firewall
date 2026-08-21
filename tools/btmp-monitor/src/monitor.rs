use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use tracing::{info, warn};

use crate::api::{ApiClient, CreateTempBanItem};
use crate::btmp::{self, FailedAttempt, ReadCursor};
use crate::config::Config;

/// Summary of one monitoring round.
///
/// In incremental mode `parsed` counts the records newly read this round (not
/// the file total); `in_window` counts total failures inside the current
/// window (maintained across rounds). Both are only printed through the
/// `info!(?summary)` in main, hence the dead_code allowance.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct RunSummary {
    pub parsed: usize,
    pub in_window: usize,
    pub banned: usize,
    pub skipped_trusted: usize,
    pub skipped_already_banned: usize,
    pub below_threshold: usize,
}

pub struct Monitor {
    config: Config,
    api: ApiClient,
    /// Incremental btmp read cursor; the first read starts at the file head.
    cursor: Option<ReadCursor>,
    /// Failure timestamps inside the window keyed by IP, maintained across rounds.
    counts: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
}

impl Monitor {
    pub fn new(config: Config) -> Result<Self> {
        let api = ApiClient::new(&config)?;
        Ok(Self {
            config,
            api,
            cursor: None,
            counts: HashMap::new(),
        })
    }

    /// Run one scan and (optional) ban round.
    pub async fn run_once(&mut self, dry_run: bool) -> Result<RunSummary> {
        let attempts = self.collect_attempts()?;
        let parsed = attempts.len();

        let cutoff = Utc::now() - chrono::Duration::seconds(self.config.ban.window_seconds as i64);

        // Incremental: merge the new records, then drop timestamps that slid
        // out of the window.
        merge_attempts(&mut self.counts, attempts, cutoff);
        let in_window: usize = self.counts.values().map(VecDeque::len).sum();

        let threshold = self.config.ban.threshold;
        let trusted = &self.config.monitor.trusted_cidrs;

        // Fetch the already-banned set for dedup. On failure, abort this round
        // (fail-closed) so unexpired bans are never resubmitted against an
        // empty set; dry-run is read-only and degrades to an empty set with a
        // warning.
        let existing = if dry_run {
            match self.api.list_temp_ban_cidrs().await {
                Ok(set) => set,
                Err(e) => {
                    warn!(
                        "failed to list existing temp-bans: {e:#}; dry-run continues with empty dedup set"
                    );
                    Default::default()
                }
            }
        } else {
            self.api
                .list_temp_ban_cidrs()
                .await
                .context("failed to list existing temp-bans; refusing to submit bans this round")?
        };

        let mut summary = RunSummary {
            parsed,
            in_window,
            ..Default::default()
        };

        // Ban candidates: above threshold, outside trusted CIDRs, not banned yet.
        let mut candidates: Vec<(IpAddr, u64)> = Vec::new();
        for (ip, times) in &self.counts {
            let count = times.len() as u64;
            if count < threshold {
                summary.below_threshold += 1;
                continue;
            }
            if is_trusted(*ip, trusted) {
                summary.skipped_trusted += 1;
                info!(%ip, count, "skip: trusted CIDR");
                continue;
            }
            let cidr = ip_cidr(*ip);
            if existing.contains(&cidr) {
                summary.skipped_already_banned += 1;
                info!(%ip, count, "skip: already banned");
                continue;
            }
            candidates.push((*ip, count));
        }

        if candidates.is_empty() {
            info!(
                parsed,
                in_window,
                below_threshold = summary.below_threshold,
                skipped_trusted = summary.skipped_trusted,
                skipped_already_banned = summary.skipped_already_banned,
                "no new IPs to ban this run"
            );
            return Ok(summary);
        }

        // Sort by failure count descending for readable logs.
        candidates.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

        for (ip, count) in &candidates {
            info!(%ip, count, threshold, "candidate for ban");
        }

        if dry_run {
            info!(
                dry_run = true,
                banned = candidates.len(),
                "dry-run: would ban IPs"
            );
            summary.banned = candidates.len();
            return Ok(summary);
        }

        let items: Vec<CreateTempBanItem> = candidates
            .iter()
            .map(|(ip, count)| CreateTempBanItem {
                cidr: ip_cidr(*ip),
                protocol: self.config.ban.protocol.clone(),
                port: self.config.ban_port(),
                duration_seconds: self.config.ban.duration_seconds,
                comment: Some(format!(
                    "{} ({} failures >= {})",
                    self.config.ban.comment, count, threshold
                )),
            })
            .collect();

        // Propagate submission failures: daemon mode logs and retries next
        // round; --once surfaces a non-zero exit code to cron/alerting.
        let n = self.api.create_temp_bans_batch(items).await?;
        summary.banned = n;
        info!(banned = n, "submitted temp-bans");

        Ok(summary)
    }

    /// Read incremental new btmp records and advance the cursor.
    fn collect_attempts(&mut self) -> Result<Vec<FailedAttempt>> {
        let path = Path::new(&self.config.monitor.btmp_path);
        let (attempts, cursor) = btmp::read_attempts(path, self.cursor)?;
        self.cursor = Some(cursor);
        Ok(attempts)
    }
}

/// Merge a batch of failure records into the window counts and drop
/// timestamps that slid out of the window.
///
/// Uses `retain` instead of front-popping to tolerate out-of-order timestamps.
fn merge_attempts(
    counts: &mut HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    attempts: Vec<FailedAttempt>,
    cutoff: DateTime<Utc>,
) {
    for a in attempts {
        if a.time >= cutoff {
            counts.entry(a.ip).or_default().push_back(a.time);
        }
    }
    counts.retain(|_, times| {
        times.retain(|t| *t >= cutoff);
        !times.is_empty()
    });
}

/// Convert an IP to a single-host CIDR (v4 -> /32, v6 -> /128), matching the
/// xdp-firewall normalization.
fn ip_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

/// Whether the IP falls into any trusted network.
fn is_trusted(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|net| net.contains(&ip))
}

/// Helper for tests/display: return the single-host CIDR of an IP.
#[allow(dead_code)]
pub fn ip_host_cidr(ip: IpAddr) -> String {
    ip_cidr(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(ip: &str, time: DateTime<Utc>) -> FailedAttempt {
        FailedAttempt {
            ip: ip.parse().unwrap(),
            time,
        }
    }

    #[test]
    fn ip_cidr_v4_and_v6() {
        assert_eq!(ip_cidr("1.2.3.4".parse().unwrap()), "1.2.3.4/32");
        assert_eq!(ip_cidr("::1".parse().unwrap()), "::1/128");
    }

    #[test]
    fn trusted_detection() {
        let cidrs: Vec<IpNet> = vec![
            "127.0.0.0/8".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        assert!(is_trusted("127.0.0.1".parse().unwrap(), &cidrs));
        assert!(is_trusted("10.5.5.5".parse().unwrap(), &cidrs));
        assert!(!is_trusted("8.8.8.8".parse().unwrap(), &cidrs));
    }

    #[test]
    fn merge_filters_by_window_and_accumulates() {
        let now = Utc::now();
        let old = now - chrono::Duration::hours(25);
        let cutoff = now - chrono::Duration::hours(24);

        let mut counts = HashMap::new();
        merge_attempts(
            &mut counts,
            vec![attempt("1.1.1.1", old), attempt("1.1.1.1", now)],
            cutoff,
        );
        assert_eq!(
            counts
                .get(&"1.1.1.1".parse::<IpAddr>().unwrap())
                .map(VecDeque::len),
            Some(1)
        );

        // A second incremental round merges new records; counts accumulate
        // per IP.
        merge_attempts(
            &mut counts,
            vec![attempt("2.2.2.2", now), attempt("1.1.1.1", now)],
            cutoff,
        );
        assert_eq!(
            counts
                .get(&"1.1.1.1".parse::<IpAddr>().unwrap())
                .map(VecDeque::len),
            Some(2)
        );
        assert_eq!(
            counts
                .get(&"2.2.2.2".parse::<IpAddr>().unwrap())
                .map(VecDeque::len),
            Some(1)
        );
    }

    #[test]
    fn merge_drops_ips_fully_outside_window() {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::hours(24);
        let mut counts = HashMap::new();
        merge_attempts(
            &mut counts,
            vec![attempt("3.3.3.3", now - chrono::Duration::hours(30))],
            cutoff,
        );
        assert!(counts.is_empty());
    }
}
