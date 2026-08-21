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

/// 单轮监控结果摘要。
///
/// 增量模式下 `parsed` 是本轮新读取的记录数(非文件累计总量);
/// `in_window` 是当前窗口内的失败总次数(跨轮维护)。
/// 两者仅在 main 的 `info!(?summary)` 中通过 Debug 输出,故允许 dead_code。
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
    /// btmp 增量读取游标;首轮读取从文件头开始。
    cursor: Option<ReadCursor>,
    /// 窗口内失败时间戳(按 IP),跨轮增量维护。
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

    /// 执行一轮扫描与(可选)封禁。
    pub async fn run_once(&mut self, dry_run: bool) -> Result<RunSummary> {
        let attempts = self.collect_attempts()?;
        let parsed = attempts.len();

        let cutoff = Utc::now() - chrono::Duration::seconds(self.config.ban.window_seconds as i64);

        // 增量:并入新记录后裁掉滑出窗口的旧时间戳。
        merge_attempts(&mut self.counts, attempts, cutoff);
        let in_window: usize = self.counts.values().map(VecDeque::len).sum();

        let threshold = self.config.ban.threshold;
        let trusted = &self.config.monitor.trusted_cidrs;

        // 拉取已封禁集合用于去重。正式封禁时失败即中止本轮(fail-closed),
        // 避免带着空集合重复提交未过期封禁;dry-run 只读展示,失败降级为空集继续。
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

        // 候选封禁 IP:超过阈值、不在可信网段、尚未封禁。
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

        // 按失败次数降序,便于日志可读。
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

        // 提交失败直接上抛:daemon 模式由主循环记日志后下轮重试,
        // --once 模式则以非零退出码暴露给 cron/告警。
        let n = self.api.create_temp_bans_batch(items).await?;
        summary.banned = n;
        info!(banned = n, "submitted temp-bans");

        Ok(summary)
    }

    /// 读取 btmp 增量新记录并推进游标。
    fn collect_attempts(&mut self) -> Result<Vec<FailedAttempt>> {
        let path = Path::new(&self.config.monitor.btmp_path);
        let (attempts, cursor) = btmp::read_attempts(path, self.cursor)?;
        self.cursor = Some(cursor);
        Ok(attempts)
    }
}

/// 把一批失败记录并入窗口计数,并裁掉滑出窗口的旧时间戳。
///
/// 用 `retain` 而非队头弹出,容忍写入方时间戳乱序。
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

/// 将 IP 转为单主机 CIDR(v4 → /32,v6 → /128),与 xdp-firewall 归一化一致。
fn ip_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

/// IP 是否落入任一可信网段。
fn is_trusted(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|net| net.contains(&ip))
}

/// 用于测试/展示的辅助:返回给定 IP 的单主机 CIDR。
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

        // 第二轮增量并入新记录,同 IP 计数累积。
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
