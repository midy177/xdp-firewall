use crate::db::entities::threat_source;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

const ALLOWED_THREAT_HOSTS_ENV: &str = "XDP_FIREWALL_ALLOWED_THREAT_HOSTS";
const MAX_THREAT_BODY_BYTES: usize = 16 * 1024 * 1024;
const THREAT_HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinThreatSource {
    pub name: &'static str,
    pub url: &'static str,
    pub format: &'static str,
    pub min_score: Option<i32>,
}

pub const BUILTIN_THREAT_SOURCES: &[BuiltinThreatSource] = &[
    BuiltinThreatSource {
        name: "ipsum",
        url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        format: "ipsum",
        min_score: Some(3),
    },
    BuiltinThreatSource {
        name: "spamhaus-drop",
        url: "https://www.spamhaus.org/drop/drop.txt",
        format: "spamhaus_drop",
        min_score: None,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatFormat {
    Cidr,
    Ips,
    Ipsum,
    #[serde(rename = "spamhaus_drop")]
    SpamhausDrop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatSource {
    pub name: String,
    pub url: String,
    pub format: ThreatFormat,
    pub min_score: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreatPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl TryFrom<threat_source::Model> for ThreatSource {
    type Error = anyhow::Error;

    fn try_from(value: threat_source::Model) -> Result<Self> {
        Ok(Self {
            name: value.name,
            url: value.url,
            format: parse_format(&value.format)?,
            min_score: value
                .min_score
                .map(|score| u32::try_from(score).context("threat min_score is negative"))
                .transpose()?,
        })
    }
}

pub async fn fetch_threat_prefixes(sources: &[ThreatSource]) -> Result<Vec<ThreatPrefix>> {
    let mut prefixes = Vec::new();
    let client = reqwest::Client::builder()
        .timeout(THREAT_HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build threat HTTP client")?;
    for source in sources {
        validate_source_url(&source.url)
            .with_context(|| format!("threat source {} has unsupported URL", source.name))?;
        let response = client
            .get(&source.url)
            .send()
            .await
            .with_context(|| format!("failed to fetch threat source {}", source.name))?
            .error_for_status()
            .with_context(|| format!("threat source {} returned HTTP error", source.name))?;
        let source_prefixes = match &source.format {
            ThreatFormat::Cidr | ThreatFormat::Ips => {
                read_limited_lines(response, MAX_THREAT_BODY_BYTES, |line| {
                    parse_line_prefix(line)
                })
                .await
            }
            ThreatFormat::Ipsum => {
                let min_score = source.min_score.unwrap_or(1);
                read_limited_lines(response, MAX_THREAT_BODY_BYTES, |line| {
                    parse_ipsum_line(line, min_score)
                })
                .await
            }
            ThreatFormat::SpamhausDrop => {
                let body = read_limited_body(response, MAX_THREAT_BODY_BYTES).await?;
                parse_spamhaus_drop(&body)
            }
        }
        .with_context(|| format!("failed to read threat source {}", source.name))?;
        prefixes.extend(source_prefixes);
    }
    Ok(normalize_prefixes(prefixes))
}

pub fn validate_source_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("invalid threat source URL '{value}'"))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => bail!("threat source URL must use http or https"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("threat source URL must not contain credentials");
    }
    let host = url
        .host_str()
        .context("threat source URL must include a host")?
        .to_ascii_lowercase();
    if !allowed_threat_hosts().contains(&host) {
        bail!("threat source host '{host}' is not allowed; add it to {ALLOWED_THREAT_HOSTS_ENV}");
    }
    Ok(())
}

async fn read_limited_body(mut response: reqwest::Response, max_bytes: usize) -> Result<String> {
    if let Some(length) = response.content_length()
        && length > max_bytes as u64
    {
        bail!("threat source response is larger than {max_bytes} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > max_bytes {
            bail!("threat source response is larger than {max_bytes} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("threat source response is not UTF-8")
}

async fn read_limited_lines<T, F>(
    mut response: reqwest::Response,
    max_bytes: usize,
    mut parse_line: F,
) -> Result<Vec<T>>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    if let Some(length) = response.content_length()
        && length > max_bytes as u64
    {
        bail!("threat source response is larger than {max_bytes} bytes");
    }
    let mut total = 0_usize;
    let mut carry = Vec::new();
    let mut parsed = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len();
        if total > max_bytes {
            bail!("threat source response is larger than {max_bytes} bytes");
        }
        carry.extend_from_slice(&chunk);
        while let Some(newline) = carry.iter().position(|byte| *byte == b'\n') {
            let mut line = carry.drain(..=newline).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = std::str::from_utf8(&line).context("threat source response is not UTF-8")?;
            if let Some(value) = parse_line(line)? {
                parsed.push(value);
            }
        }
    }
    if !carry.is_empty() {
        if carry.last() == Some(&b'\r') {
            carry.pop();
        }
        let line = std::str::from_utf8(&carry).context("threat source response is not UTF-8")?;
        if let Some(value) = parse_line(line)? {
            parsed.push(value);
        }
    }
    Ok(parsed)
}

fn allowed_threat_hosts() -> HashSet<String> {
    let mut hosts = BUILTIN_THREAT_SOURCES
        .iter()
        .filter_map(|source| reqwest::Url::parse(source.url).ok())
        .filter_map(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
        .collect::<HashSet<_>>();
    if let Ok(configured) = std::env::var(ALLOWED_THREAT_HOSTS_ENV) {
        hosts.extend(
            configured
                .split(',')
                .map(str::trim)
                .filter(|host| !host.is_empty())
                .map(str::to_ascii_lowercase),
        );
    }
    hosts
}

fn parse_line_prefixes(body: &str) -> Result<Vec<ThreatPrefix>> {
    let mut prefixes = Vec::new();
    for line in body.lines() {
        if let Some(prefix) = parse_line_prefix(line)? {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

fn parse_line_prefix(line: &str) -> Result<Option<ThreatPrefix>> {
    let Some(token) = first_prefix_token(line) else {
        return Ok(None);
    };
    Ok(Some(parse_prefix(token)?))
}

fn parse_ipsum_line(line: &str, min_score: u32) -> Result<Option<ThreatPrefix>> {
    let clean = strip_comment(line);
    let mut parts = clean.split_whitespace();
    let Some(ip) = parts.next() else {
        return Ok(None);
    };
    let score = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1);
    if score >= min_score {
        return Ok(Some(parse_prefix(ip)?));
    }
    Ok(None)
}

fn parse_spamhaus_drop(body: &str) -> Result<Vec<ThreatPrefix>> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        let mut prefixes = Vec::new();
        collect_json_cidrs(&value, &mut prefixes)?;
        if !prefixes.is_empty() {
            return Ok(prefixes);
        }
    }
    parse_line_prefixes(body)
}

fn collect_json_cidrs(value: &Value, prefixes: &mut Vec<ThreatPrefix>) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_json_cidrs(value, prefixes)?;
            }
        }
        Value::Object(map) => {
            if let Some(Value::String(cidr)) = map.get("cidr").or_else(|| map.get("prefix")) {
                prefixes.push(parse_prefix(cidr)?);
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_prefix(value: &str) -> Result<ThreatPrefix> {
    let value = value.trim().trim_matches(',').trim_matches('"');
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(match net {
            IpNet::V4(net) => ThreatPrefix {
                addr: IpAddr::V4(net.network()),
                prefix: net.prefix_len(),
            },
            IpNet::V6(net) => ThreatPrefix {
                addr: IpAddr::V6(net.network()),
                prefix: net.prefix_len(),
            },
        });
    }
    let addr = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid threat IP/CIDR '{value}'"))?;
    Ok(ThreatPrefix {
        addr,
        prefix: if addr.is_ipv4() { 32 } else { 128 },
    })
}

fn first_prefix_token(line: &str) -> Option<&str> {
    strip_comment(line)
        .split_whitespace()
        .find(|token| token.parse::<IpAddr>().is_ok() || token.contains('/'))
}

fn strip_comment(line: &str) -> &str {
    line.split(['#', ';']).next().unwrap_or("").trim()
}

fn normalize_prefixes(prefixes: Vec<ThreatPrefix>) -> Vec<ThreatPrefix> {
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();
    for prefix in prefixes {
        if unique.insert(prefix) {
            normalized.push(prefix);
        }
    }
    normalized.sort_by_key(|prefix| (prefix.addr.is_ipv6(), prefix.addr, prefix.prefix));
    normalized
}

fn parse_format(value: &str) -> Result<ThreatFormat> {
    match value.to_ascii_lowercase().as_str() {
        "cidr" => Ok(ThreatFormat::Cidr),
        "ips" => Ok(ThreatFormat::Ips),
        "ipsum" => Ok(ThreatFormat::Ipsum),
        "spamhaus_drop" | "spamhaus-drop" => Ok(ThreatFormat::SpamhausDrop),
        _ => bail!("unsupported threat format '{value}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipsum_with_min_score() {
        assert!(parse_ipsum_line("1.1.1.1 2", 3).unwrap().is_none());
        let parsed = parse_ipsum_line("2.2.2.0/24 5", 3).unwrap().unwrap();
        assert_eq!(parsed.prefix, 24);
    }

    #[test]
    fn builtin_sources_match_sigproxy_defaults() {
        assert_eq!(
            BUILTIN_THREAT_SOURCES
                .iter()
                .map(|source| source.name)
                .collect::<Vec<_>>(),
            ["ipsum", "spamhaus-drop"]
        );
        assert_eq!(BUILTIN_THREAT_SOURCES[0].min_score, Some(3));
        assert_eq!(BUILTIN_THREAT_SOURCES[1].format, "spamhaus_drop");
    }

    #[test]
    fn rejects_threat_url_credentials() {
        let err = validate_source_url("https://user:secret@raw.githubusercontent.com/feed.txt")
            .unwrap_err();
        assert!(err.to_string().contains("must not contain credentials"));
    }
}
