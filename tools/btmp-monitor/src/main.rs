mod api;
mod btmp;
mod config;
mod monitor;

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

/// 监控 btmp 失败登录(直接解析 /var/log/btmp 二进制),
/// 对暴力破解 IP 自动调用 xdp-firewall API 封禁。
/// 所有参数均可通过环境变量覆盖,见各项说明。
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// xdp-firewall 控制平面 API 地址。
    #[arg(
        long,
        env = "BTMP_MONITOR_API_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    api_url: String,

    /// 与 xdp-firewall 的 XDP_FIREWALL_API_TOKEN 一致。
    #[arg(long, env = "XDP_FIREWALL_API_TOKEN")]
    api_token: Option<String>,

    /// 触发封禁所需的失败登录次数。
    #[arg(long, env = "BTMP_MONITOR_THRESHOLD", default_value_t = 5)]
    threshold: u64,

    /// 统计窗口(秒)。
    #[arg(long, env = "BTMP_MONITOR_WINDOW_SECONDS", default_value_t = 86_400)]
    window_seconds: u64,

    /// 封禁持续时长(秒),xdp-firewall API 上限为 31_536_000(约 1 年)。
    #[arg(long, env = "BTMP_MONITOR_DURATION_SECONDS", default_value_t = 86_400)]
    duration_seconds: i64,

    /// 封禁协议:"any" | "tcp" | "udp";any 表示屏蔽该 IP 所有协议。
    #[arg(long, env = "BTMP_MONITOR_PROTOCOL", default_value = "any")]
    protocol: String,

    /// 仅当 protocol != "any" 时生效,取值 1..=65535。
    #[arg(long, env = "BTMP_MONITOR_PORT", default_value_t = 0)]
    port: i32,

    /// 写入 temp-ban 记录的备注。
    #[arg(
        long,
        env = "BTMP_MONITOR_COMMENT",
        default_value = "btmp auto-ban: brute-force SSH"
    )]
    comment: String,

    /// btmp 文件路径。
    #[arg(long, env = "BTMP_MONITOR_BTMP_PATH", default_value = "/var/log/btmp")]
    btmp_path: String,

    /// 永不封禁的可信网段(自身节点、内网等);可多次指定,环境变量用逗号分隔。
    #[arg(
        long,
        env = "BTMP_MONITOR_TRUSTED_CIDRS",
        value_delimiter = ',',
        default_values_t = ["127.0.0.0/8".to_string(), "::1/128".to_string()]
    )]
    trusted_cidr: Vec<String>,

    /// 单次运行后退出(适合 cron)。
    #[arg(long)]
    once: bool,

    /// 只解析并打印候选 IP,不调用封禁 API。
    #[arg(long)]
    dry_run: bool,

    /// daemon 轮询间隔(秒)。
    #[arg(long, env = "BTMP_MONITOR_INTERVAL", default_value_t = 60)]
    interval: u64,
}

impl Cli {
    /// 组装运行配置并校验。
    fn to_config(&self) -> Result<config::Config> {
        let trusted_cidrs = self
            .trusted_cidr
            .iter()
            .map(|value| value.parse())
            .collect::<Result<Vec<_>, _>>()
            .context("invalid --trusted-cidr value")?;
        let config = config::Config {
            api_url: self.api_url.trim_end_matches('/').to_string(),
            api_token: self.api_token.clone().unwrap_or_default(),
            ban: config::BanConfig {
                threshold: self.threshold,
                window_seconds: self.window_seconds,
                duration_seconds: self.duration_seconds,
                protocol: self.protocol.clone(),
                port: self.port,
                comment: self.comment.clone(),
            },
            monitor: config::MonitorConfig {
                btmp_path: self.btmp_path.clone(),
                trusted_cidrs,
            },
        };
        config.validate()?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = cli.to_config()?;

    if !cli.dry_run && config.api_token.trim().is_empty() {
        bail!("--api-token (或环境变量 XDP_FIREWALL_API_TOKEN) 是必需的;仅 --dry-run 可省略");
    }

    info!(
        api_url = %config.api_url,
        btmp_path = %config.monitor.btmp_path,
        threshold = config.ban.threshold,
        window_seconds = config.ban.window_seconds,
        duration_seconds = config.ban.duration_seconds,
        protocol = %config.ban.protocol,
        interval_secs = cli.interval,
        once = cli.once,
        dry_run = cli.dry_run,
        "btmp-monitor starting"
    );

    let mut monitor = monitor::Monitor::new(config)?;

    if cli.once {
        let summary = monitor.run_once(cli.dry_run).await?;
        info!(?summary, "run complete");
        return Ok(());
    }

    run_daemon(monitor, cli.dry_run, cli.interval).await
}

/// daemon 模式:按间隔循环,收到 SIGTERM/SIGINT 优雅退出。
async fn run_daemon(
    mut monitor: monitor::Monitor,
    dry_run: bool,
    interval_secs: u64,
) -> Result<()> {
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;

    let interval = Duration::from_secs(interval_secs.max(1));
    info!(?interval, "daemon mode: polling btmp");

    loop {
        if let Err(e) = monitor.run_once(dry_run).await {
            tracing::warn!(error = %format!("{e:#}"), "run failed; will retry next interval");
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = term.recv() => {
                info!("received SIGTERM, shutting down");
                break;
            }
            _ = int.recv() => {
                info!("received SIGINT, shutting down");
                break;
            }
        }
    }

    Ok(())
}
