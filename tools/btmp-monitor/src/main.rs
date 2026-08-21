mod api;
mod btmp;
mod config;
mod monitor;

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

/// Monitor failed SSH logins by parsing `/var/log/btmp` binary records directly
/// and auto-ban brute-force source IPs through the xdp-firewall API.
/// Every option can also be provided through environment variables; see each item.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// xdp-firewall control-plane API base URL.
    #[arg(
        long,
        env = "BTMP_MONITOR_API_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    api_url: String,

    /// Must match xdp-firewall's XDP_FIREWALL_API_TOKEN.
    #[arg(long, env = "XDP_FIREWALL_API_TOKEN")]
    api_token: Option<String>,

    /// Failed logins required before banning an IP.
    #[arg(long, env = "BTMP_MONITOR_THRESHOLD", default_value_t = 5)]
    threshold: u64,

    /// Counting window in seconds.
    #[arg(long, env = "BTMP_MONITOR_WINDOW_SECONDS", default_value_t = 86_400)]
    window_seconds: u64,

    /// Ban duration in seconds (default 10 minutes); the xdp-firewall API
    /// caps it at 31_536_000 (~1 year).
    #[arg(long, env = "BTMP_MONITOR_DURATION_SECONDS", default_value_t = 600)]
    duration_seconds: i64,

    /// Ban protocol: "any" | "tcp" | "udp"; "any" blocks every protocol for the IP.
    #[arg(long, env = "BTMP_MONITOR_PROTOCOL", default_value = "any")]
    protocol: String,

    /// Only used when protocol != "any"; range 1..=65535.
    #[arg(long, env = "BTMP_MONITOR_PORT", default_value_t = 0)]
    port: i32,

    /// Comment written to the temp-ban record.
    #[arg(
        long,
        env = "BTMP_MONITOR_COMMENT",
        default_value = "btmp auto-ban: brute-force SSH"
    )]
    comment: String,

    /// Path to the btmp file.
    #[arg(long, env = "BTMP_MONITOR_BTMP_PATH", default_value = "/var/log/btmp")]
    btmp_path: String,

    /// CIDRs that are never banned (own nodes, internal networks);
    /// repeat the flag, or use a comma-separated value in the env variable.
    #[arg(
        long,
        env = "BTMP_MONITOR_TRUSTED_CIDRS",
        value_delimiter = ',',
        default_values_t = ["127.0.0.0/8".to_string(), "::1/128".to_string()]
    )]
    trusted_cidr: Vec<String>,

    /// Run one scan and exit (for cron).
    #[arg(long)]
    once: bool,

    /// Print ban candidates and the parameters a real run would submit;
    /// makes no API requests at all.
    #[arg(long)]
    dry_run: bool,

    /// Daemon poll interval in seconds.
    #[arg(long, env = "BTMP_MONITOR_INTERVAL", default_value_t = 60)]
    interval: u64,
}

impl Cli {
    /// Assemble and validate the runtime config.
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
        bail!("--api-token (or env XDP_FIREWALL_API_TOKEN) is required unless --dry-run is set");
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

/// Daemon mode: loop on the interval, exit gracefully on SIGTERM/SIGINT.
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
