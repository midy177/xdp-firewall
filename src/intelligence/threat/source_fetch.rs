use anyhow::{Context, Result, bail};

use super::{
    MAX_THREAT_BODY_BYTES, THREAT_HTTP_MAX_REDIRECTS, THREAT_HTTP_TIMEOUT, ThreatFormat,
    ThreatPrefix, ThreatSource,
};
use crate::intelligence::http_limited::{read_limited_body, read_limited_lines};

mod parser;
mod prefix;

#[cfg(test)]
pub(super) use parser::parse_ipsum_line;
pub(super) use parser::{parse_lenient_ipsum_line, parse_lenient_line_prefix, parse_spamhaus_drop};
pub(super) use prefix::{
    normalize_prefixes, parse_prefix, prefix_to_cidr, threat_prefix_fingerprint,
};

pub(super) async fn fetch_threat_source_prefixes(
    client: &reqwest::Client,
    source: &ThreatSource,
) -> Result<Vec<ThreatPrefix>> {
    validate_source_url(&source.url)
        .with_context(|| format!("threat source {} has unsupported URL", source.name))?;
    let response = client
        .get(&source.url)
        .send()
        .await
        .with_context(|| format!("failed to fetch threat source {}", source.name))?;
    if response.status().is_redirection() {
        bail!(
            "threat source {} returned an unsupported redirect",
            source.name
        );
    }
    let response = response
        .error_for_status()
        .with_context(|| format!("threat source {} returned HTTP error", source.name))?;
    match &source.format {
        ThreatFormat::Cidr | ThreatFormat::Ips => {
            read_limited_lines(response, MAX_THREAT_BODY_BYTES, "threat source", |line| {
                Ok(parse_lenient_line_prefix(line, source.format.label()))
            })
            .await
        }
        ThreatFormat::Voipbl => {
            read_limited_lines(response, MAX_THREAT_BODY_BYTES, "threat source", |line| {
                Ok(parse_lenient_line_prefix(line, source.format.label()))
            })
            .await
        }
        ThreatFormat::Ipsum => {
            let min_score = source.min_score.unwrap_or(1);
            read_limited_lines(response, MAX_THREAT_BODY_BYTES, "threat source", |line| {
                Ok(parse_lenient_ipsum_line(line, min_score))
            })
            .await
        }
        ThreatFormat::SpamhausDrop => {
            let body = read_limited_body(response, MAX_THREAT_BODY_BYTES, "threat source").await?;
            parse_spamhaus_drop(&body)
        }
    }
    .with_context(|| format!("failed to read threat source {}", source.name))
}

pub(super) fn threat_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(THREAT_HTTP_TIMEOUT)
        .redirect(threat_redirect_policy())
        .build()
        .context("failed to build threat HTTP client")
}

pub(super) fn threat_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > THREAT_HTTP_MAX_REDIRECTS {
            return attempt.error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many threat source redirects",
            ));
        }
        if let Err(err) = validate_source_url_parts(attempt.url()) {
            return attempt.error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("threat source redirect target is unsupported: {err}"),
            ));
        }
        attempt.follow()
    })
}

pub fn validate_source_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("invalid threat source URL '{value}'"))?;
    validate_source_url_parts(&url)?;
    Ok(())
}

fn validate_source_url_parts(url: &reqwest::Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        _ => bail!("threat source URL must use http or https"),
    }
}
