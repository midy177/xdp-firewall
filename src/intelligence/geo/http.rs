use crate::intelligence::http_limited::{read_limited_body, read_limited_lines};
use anyhow::{Context, Result};
use reqwest::header::HeaderName;

use super::IPDENY_HTTP_TIMEOUT;

pub(super) fn header_string(
    headers: &reqwest::header::HeaderMap,
    name: HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn ipdeny_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(IPDENY_HTTP_TIMEOUT)
        .build()
        .context("failed to build IPdeny HTTP client")
}

pub(super) async fn fetch_text_limited(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("geo provider returned error for {url}"))?;
    read_limited_body(response, max_bytes, "geo provider").await
}

pub(super) async fn response_lines_limited<T, F>(
    response: reqwest::Response,
    max_bytes: usize,
    parse_line: F,
) -> Result<Vec<T>>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    read_limited_lines(response, max_bytes, "geo provider", parse_line).await
}
