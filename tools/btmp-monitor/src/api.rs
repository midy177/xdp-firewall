use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::config::Config;

/// xdp-firewall API 单次批量创建的条数上限,与主仓库 `MAX_BATCH_SIZE` 一致。
const MAX_BATCH_ITEMS: usize = 500;

/// 单个 HTTP 请求的总超时,防止 API 挂起时 daemon 轮询停摆。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 一次封禁请求(对应 xdp-firewall `CreateTempBanRequest`)。
#[derive(Debug, Serialize)]
pub struct CreateTempBanItem {
    pub cidr: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    pub duration_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchRequest<'a> {
    items: &'a [CreateTempBanItem],
}

/// `/temp-bans` 分页响应中的单条记录(仅取 cidr)。
#[derive(Debug, Deserialize)]
struct TempBanModel {
    cidr: String,
}

#[derive(Debug, Deserialize)]
struct Page {
    items: Vec<TempBanModel>,
    total_pages: u64,
}

/// 封装对 xdp-firewall 控制平面 API 的访问。
pub struct ApiClient {
    base_url: String,
    token: String,
    http: Client,
}

impl ApiClient {
    pub fn new(config: &Config) -> Result<Self> {
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            base_url: config.api_url.clone(),
            token: config.api_token.clone(),
            http,
        })
    }

    /// 拉取所有未过期的 temp-ban,返回其归一化 CIDR 集合。
    pub async fn list_temp_ban_cidrs(&self) -> Result<std::collections::HashSet<String>> {
        let mut cidrs = std::collections::HashSet::new();
        let mut page: u64 = 1;
        const PAGE_SIZE: u64 = 500;

        loop {
            let url = format!(
                "{}/temp-bans?page={page}&page_size={PAGE_SIZE}",
                self.base_url
            );
            let resp = self
                .http
                .get(&url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", self.token),
                )
                .send()
                .await
                .with_context(|| format!("GET {url} failed"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("GET /temp-bans returned {status}: {}", body.trim());
            }

            let body: Page = resp
                .json()
                .await
                .context("failed to decode /temp-bans response")?;

            for item in &body.items {
                cidrs.insert(item.cidr.clone());
            }

            if page >= body.total_pages || body.items.is_empty() {
                break;
            }
            page += 1;
        }

        Ok(cidrs)
    }

    /// 批量创建 temp-ban,超过 API 单次上限时自动分块提交。返回提交条数。
    ///
    /// 分块逐个提交:中途某块失败时,前面已成功的块不会回滚,错误会附带
    /// 已提交数量;剩余候选由下一轮扫描重试。
    pub async fn create_temp_bans_batch(&self, items: Vec<CreateTempBanItem>) -> Result<usize> {
        let mut submitted = 0usize;
        for chunk in items.chunks(MAX_BATCH_ITEMS) {
            match self.create_temp_ban_chunk(chunk).await {
                Ok(n) => submitted += n,
                Err(e) => {
                    return Err(e.context(format!(
                        "temp-ban chunk failed; {submitted} items already submitted in earlier chunks"
                    )));
                }
            }
        }
        Ok(submitted)
    }

    /// 提交单个不超过 `MAX_BATCH_ITEMS` 的分块。
    async fn create_temp_ban_chunk(&self, chunk: &[CreateTempBanItem]) -> Result<usize> {
        let count = chunk.len();
        let url = format!("{}/temp-bans/batch", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.token),
            )
            .json(&BatchRequest { items: chunk })
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;

        let status = resp.status();
        if status != StatusCode::CREATED {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST /temp-bans/batch returned {status}: {}", body.trim());
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            api_url: "http://127.0.0.1:9".to_string(),
            api_token: "t".to_string(),
            ban: crate::config::BanConfig {
                threshold: 5,
                window_seconds: 86_400,
                duration_seconds: 60,
                protocol: "any".to_string(),
                port: 0,
                comment: "test".to_string(),
            },
            monitor: crate::config::MonitorConfig {
                btmp_path: "/var/log/btmp".to_string(),
                trusted_cidrs: Vec::new(),
            },
        }
    }

    /// 钉住与主仓库 `control_plane/api/mod.rs` 的 `MAX_BATCH_SIZE` 的一致性。
    #[test]
    fn batch_limit_matches_server() {
        assert_eq!(MAX_BATCH_ITEMS, 500);
    }

    /// 空输入直接短路,不应发起任何网络请求。
    #[tokio::test]
    async fn empty_batch_short_circuits_without_network() {
        let client = ApiClient::new(&test_config()).unwrap();
        assert_eq!(client.create_temp_bans_batch(Vec::new()).await.unwrap(), 0);
    }
}
