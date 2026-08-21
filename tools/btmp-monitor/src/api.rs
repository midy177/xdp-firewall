use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::config::Config;

/// Per-request batch cap of the xdp-firewall API, matching the main repo's
/// `MAX_BATCH_SIZE`.
const MAX_BATCH_ITEMS: usize = 500;

/// Total per-request HTTP timeout so a hung API cannot stall the daemon poll loop.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// One ban request item (mirrors xdp-firewall `CreateTempBanRequest`).
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

/// One record of the paginated `/temp-bans` response (cidr only).
#[derive(Debug, Deserialize)]
struct TempBanModel {
    cidr: String,
}

#[derive(Debug, Deserialize)]
struct Page {
    items: Vec<TempBanModel>,
    total_pages: u64,
}

/// Client for the xdp-firewall control-plane API.
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

    /// Fetch all unexpired temp-bans and return their normalized CIDR set.
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

    /// Batch-create temp-bans, auto-chunking past the per-request cap;
    /// returns the submitted count.
    ///
    /// Chunks are submitted one by one: when a chunk fails, earlier chunks
    /// stay committed and the error carries the already-submitted count;
    /// remaining candidates retry on the next scan.
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

    /// Submit one chunk of at most `MAX_BATCH_ITEMS` entries.
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

    /// Pin consistency with the main repo's `MAX_BATCH_SIZE`.
    #[test]
    fn batch_limit_matches_server() {
        assert_eq!(MAX_BATCH_ITEMS, 500);
    }

    /// Empty input short-circuits without any network request.
    #[tokio::test]
    async fn empty_batch_short_circuits_without_network() {
        let client = ApiClient::new(&test_config()).unwrap();
        assert_eq!(client.create_temp_bans_batch(Vec::new()).await.unwrap(), 0);
    }
}
