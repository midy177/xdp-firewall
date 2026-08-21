use anyhow::{Result, bail};
use ipnet::IpNet;

/// 运行参数,由 main 从 CLI 参数/环境变量组装。
#[derive(Debug, Clone)]
pub struct Config {
    pub api_url: String,
    pub api_token: String,
    pub ban: BanConfig,
    pub monitor: MonitorConfig,
}

#[derive(Debug, Clone)]
pub struct BanConfig {
    pub threshold: u64,
    pub window_seconds: u64,
    pub duration_seconds: i64,
    pub protocol: String,
    pub port: i32,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub btmp_path: String,
    pub trusted_cidrs: Vec<IpNet>,
}

/// API 接受的最大封禁时长(秒),见 xdp-firewall `temp_bans/input.rs`。
const MAX_TEMP_BAN_SECONDS: i64 = 31_536_000;

impl Config {
    /// 校验由 CLI/环境变量组装出的参数组合。
    ///
    /// token 为空不在本校验范围:dry-run 允许无 token,是否放行由 main 决定。
    pub fn validate(&self) -> Result<()> {
        if self.api_url.is_empty() {
            bail!("api_url must not be empty");
        }
        if self.ban.threshold < 1 {
            bail!("threshold must be >= 1");
        }
        if self.ban.window_seconds == 0 {
            bail!("window-seconds must be > 0");
        }
        if !(1..=MAX_TEMP_BAN_SECONDS).contains(&self.ban.duration_seconds) {
            bail!("duration-seconds must be between 1 and {MAX_TEMP_BAN_SECONDS}");
        }
        match self.ban.protocol.as_str() {
            "any" => {
                if self.ban.port != 0 {
                    bail!("port must be 0 when protocol is \"any\"");
                }
            }
            "tcp" | "udp" => {
                if !(1..=65535).contains(&self.ban.port) {
                    bail!(
                        "port must be in 1..=65535 when protocol is \"{}\"",
                        self.ban.protocol
                    );
                }
            }
            other => bail!("protocol must be one of: any, tcp, udp (got {other:?})"),
        }
        if self.monitor.btmp_path.trim().is_empty() {
            bail!("btmp-path must not be empty");
        }
        Ok(())
    }

    /// 当 protocol == "any" 时返回 None,与 API 的 `Option<i32>` 对齐。
    pub fn ban_port(&self) -> Option<i32> {
        if self.ban.protocol == "any" {
            None
        } else {
            Some(self.ban.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            api_url: "http://127.0.0.1:8080".to_string(),
            api_token: "tok".to_string(),
            ban: BanConfig {
                threshold: 5,
                window_seconds: 86_400,
                duration_seconds: 3_600,
                protocol: "any".to_string(),
                port: 0,
                comment: "x".to_string(),
            },
            monitor: MonitorConfig {
                btmp_path: "/var/log/btmp".to_string(),
                trusted_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
            },
        }
    }

    #[test]
    fn valid_config_passes() {
        let cfg = base_config();
        cfg.validate().unwrap();
        assert_eq!(cfg.ban_port(), None);
    }

    #[test]
    fn rejects_zero_duration() {
        let mut cfg = base_config();
        cfg.ban.duration_seconds = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_port_with_any_protocol() {
        let mut cfg = base_config();
        cfg.ban.port = 22;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tcp_requires_valid_port() {
        let mut cfg = base_config();
        cfg.ban.protocol = "tcp".to_string();
        cfg.ban.port = 22;
        cfg.validate().unwrap();
        assert_eq!(cfg.ban_port(), Some(22));
    }

    #[test]
    fn rejects_empty_btmp_path() {
        let mut cfg = base_config();
        cfg.monitor.btmp_path = " ".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_threshold() {
        let mut cfg = base_config();
        cfg.ban.threshold = 0;
        assert!(cfg.validate().is_err());
    }
}
