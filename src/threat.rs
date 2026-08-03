use crate::db;
use crate::db::entities::{threat_source, threat_source_state};
use crate::firewall;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, TransactionTrait,
    sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tracing::warn;

const ALLOWED_THREAT_HOSTS_ENV: &str = "XDP_FIREWALL_ALLOWED_THREAT_HOSTS";
const MAX_THREAT_BODY_BYTES: usize = 16 * 1024 * 1024;
const THREAT_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const REFRESH_LOCK_POLICY_NAME: &str = "__threat_refresh_lock__";
const REFRESH_LOCK_SOURCE_NAME: &str = firewall::DEFAULT_POLICY_NAME;
const REFRESH_LOCK_STALE_SECONDS: i64 = 900;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRefreshReport {
    pub enabled_source_count: u64,
    pub changed_source_count: u64,
    pub prefix_count: usize,
    pub refreshed: bool,
    pub refresh_status: String,
    #[serde(default)]
    pub cached: bool,
    #[serde(default)]
    pub running: bool,
}

impl ThreatRefreshReport {
    pub fn empty(refresh_status: impl Into<String>) -> Self {
        Self {
            enabled_source_count: 0,
            changed_source_count: 0,
            prefix_count: 0,
            refreshed: false,
            refresh_status: refresh_status.into(),
            cached: false,
            running: false,
        }
    }
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
        prefixes.extend(fetch_threat_source_prefixes(&client, source).await?);
    }
    Ok(normalize_prefixes(prefixes))
}

pub async fn refresh_enabled_threat_sources(
    db: &DatabaseConnection,
) -> Result<ThreatRefreshReport> {
    let Some(_guard) = ThreatRefreshDbLock::try_acquire(db).await? else {
        return Ok(ThreatRefreshReport {
            running: true,
            ..ThreatRefreshReport::empty("running")
        });
    };
    let sources = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?;
    let enabled_source_count = sources.len() as u64;
    if enabled_source_count == 0 {
        return Ok(ThreatRefreshReport {
            enabled_source_count,
            ..ThreatRefreshReport::empty("empty")
        });
    }
    let sources = sources
        .into_iter()
        .map(ThreatSource::try_from)
        .collect::<Result<Vec<_>>>()?;
    let existing = threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .all(db)
        .await?
        .into_iter()
        .map(|row| (row.source_name.clone(), row))
        .collect::<std::collections::HashMap<_, _>>();
    let client = reqwest::Client::builder()
        .timeout(THREAT_HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build threat HTTP client")?;
    let mut states = Vec::with_capacity(sources.len());
    let mut changed_source_count = 0_u64;
    let mut prefix_count = 0_usize;
    let now = chrono::Utc::now().naive_utc();
    for source in &sources {
        let prefixes = fetch_threat_source_prefixes(&client, source).await?;
        let prefixes = normalize_prefixes(prefixes);
        let fingerprint = threat_prefix_fingerprint(&prefixes);
        prefix_count += prefixes.len();
        let changed = existing
            .get(&source.name)
            .is_none_or(|state| state.fingerprint != fingerprint);
        if changed {
            changed_source_count += 1;
        }
        states.push(threat_source_state::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            source_name: Set(source.name.clone()),
            fingerprint: Set(fingerprint),
            prefix_count: Set(prefixes
                .len()
                .try_into()
                .context("threat prefix count overflowed")?),
            last_checked_at: Set(now),
            last_changed_at: Set(if changed {
                Some(now)
            } else {
                existing
                    .get(&source.name)
                    .and_then(|state| state.last_changed_at)
            }),
            updated_at: Set(now),
            ..Default::default()
        });
    }
    let txn = db.begin().await?;
    for state in states {
        threat_source_state::Entity::insert(state)
            .on_conflict(
                OnConflict::columns([
                    threat_source_state::Column::PolicyName,
                    threat_source_state::Column::SourceName,
                ])
                .update_columns([
                    threat_source_state::Column::Fingerprint,
                    threat_source_state::Column::PrefixCount,
                    threat_source_state::Column::LastCheckedAt,
                    threat_source_state::Column::LastChangedAt,
                    threat_source_state::Column::UpdatedAt,
                ])
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await?;
    }
    if changed_source_count > 0 {
        db::next_policy_version_in_transaction(&txn, firewall::DEFAULT_POLICY_NAME).await?;
    }
    txn.commit().await?;
    Ok(ThreatRefreshReport {
        enabled_source_count,
        changed_source_count,
        prefix_count,
        refreshed: changed_source_count > 0,
        refresh_status: if changed_source_count > 0 {
            "changed".to_string()
        } else {
            "unchanged".to_string()
        },
        cached: false,
        running: false,
    })
}

struct ThreatRefreshDbLock {
    db: DatabaseConnection,
    owner: String,
}

impl ThreatRefreshDbLock {
    async fn try_acquire(db: &DatabaseConnection) -> Result<Option<Self>> {
        let now = chrono::Utc::now().naive_utc();
        let owner = format!(
            "{}:{}",
            std::process::id(),
            now.and_utc()
                .timestamp_nanos_opt()
                .unwrap_or_else(|| now.and_utc().timestamp_micros() * 1_000)
        );
        threat_source_state::Entity::insert(threat_source_state::ActiveModel {
            policy_name: Set(REFRESH_LOCK_POLICY_NAME.to_string()),
            source_name: Set(REFRESH_LOCK_SOURCE_NAME.to_string()),
            fingerprint: Set("idle".to_string()),
            prefix_count: Set(0),
            last_checked_at: Set(now),
            last_changed_at: Set(None),
            updated_at: Set(now),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::columns([
                threat_source_state::Column::PolicyName,
                threat_source_state::Column::SourceName,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(db)
        .await?;

        let Some(existing) = threat_source_state::Entity::find()
            .filter(threat_source_state::Column::PolicyName.eq(REFRESH_LOCK_POLICY_NAME))
            .filter(threat_source_state::Column::SourceName.eq(REFRESH_LOCK_SOURCE_NAME))
            .one(db)
            .await?
        else {
            bail!("failed to initialize threat source refresh database lock");
        };

        let is_running = existing.fingerprint.starts_with("running:");
        let age_seconds = (now - existing.updated_at).num_seconds();
        if is_running && age_seconds < REFRESH_LOCK_STALE_SECONDS {
            return Ok(None);
        }

        let updated = threat_source_state::Entity::update_many()
            .filter(threat_source_state::Column::PolicyName.eq(REFRESH_LOCK_POLICY_NAME))
            .filter(threat_source_state::Column::SourceName.eq(REFRESH_LOCK_SOURCE_NAME))
            .filter(threat_source_state::Column::UpdatedAt.eq(existing.updated_at))
            .col_expr(
                threat_source_state::Column::Fingerprint,
                sea_orm::sea_query::Expr::value(format!("running:{owner}")),
            )
            .col_expr(
                threat_source_state::Column::LastCheckedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .col_expr(
                threat_source_state::Column::LastChangedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .col_expr(
                threat_source_state::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .exec(db)
            .await?;
        Ok((updated.rows_affected > 0).then(|| Self {
            db: db.clone(),
            owner,
        }))
    }
}

impl Drop for ThreatRefreshDbLock {
    fn drop(&mut self) {
        let db = self.db.clone();
        let owner = self.owner.clone();
        tokio::spawn(async move {
            let now = chrono::Utc::now().naive_utc();
            if let Err(err) = threat_source_state::Entity::update_many()
                .filter(threat_source_state::Column::PolicyName.eq(REFRESH_LOCK_POLICY_NAME))
                .filter(threat_source_state::Column::SourceName.eq(REFRESH_LOCK_SOURCE_NAME))
                .filter(threat_source_state::Column::Fingerprint.eq(format!("running:{owner}")))
                .col_expr(
                    threat_source_state::Column::Fingerprint,
                    sea_orm::sea_query::Expr::value("idle"),
                )
                .col_expr(
                    threat_source_state::Column::UpdatedAt,
                    sea_orm::sea_query::Expr::value(now),
                )
                .exec(&db)
                .await
            {
                warn!(error = %err, "failed to release threat source refresh database lock");
            }
        });
    }
}

pub async fn enabled_threat_source_states_missing(db: &DatabaseConnection) -> Result<bool> {
    let sources = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?;
    for source in sources {
        let has_state = threat_source_state::Entity::find()
            .filter(threat_source_state::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
            .filter(threat_source_state::Column::SourceName.eq(source.name))
            .one(db)
            .await?
            .is_some();
        if !has_state {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn fetch_threat_source_prefixes(
    client: &reqwest::Client,
    source: &ThreatSource,
) -> Result<Vec<ThreatPrefix>> {
    validate_source_url(&source.url)
        .with_context(|| format!("threat source {} has unsupported URL", source.name))?;
    let response = client
        .get(&source.url)
        .send()
        .await
        .with_context(|| format!("failed to fetch threat source {}", source.name))?
        .error_for_status()
        .with_context(|| format!("threat source {} returned HTTP error", source.name))?;
    match &source.format {
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
    .with_context(|| format!("failed to read threat source {}", source.name))
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

fn threat_prefix_fingerprint(prefixes: &[ThreatPrefix]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for prefix in prefixes {
        for byte in prefix.addr.to_string().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= u64::from(b'/');
        hash = hash.wrapping_mul(0x100000001b3);
        for byte in prefix.prefix.to_string().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= u64::from(b'\n');
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
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
    use sea_orm::{ActiveModelTrait, ConnectOptions, Database};

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

    #[test]
    fn threat_prefix_fingerprint_changes_with_prefix_set() {
        let first = normalize_prefixes(vec![
            parse_prefix("203.0.113.10").unwrap(),
            parse_prefix("198.51.100.0/24").unwrap(),
        ]);
        let reordered = normalize_prefixes(vec![
            parse_prefix("198.51.100.0/24").unwrap(),
            parse_prefix("203.0.113.10").unwrap(),
        ]);
        let changed = normalize_prefixes(vec![
            parse_prefix("203.0.113.11").unwrap(),
            parse_prefix("198.51.100.0/24").unwrap(),
        ]);

        assert_eq!(
            threat_prefix_fingerprint(&first),
            threat_prefix_fingerprint(&reordered)
        );
        assert_ne!(
            threat_prefix_fingerprint(&first),
            threat_prefix_fingerprint(&changed)
        );
    }

    #[tokio::test]
    async fn enabled_threat_source_states_missing_detects_enabled_source_without_state() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();

        assert!(!enabled_threat_source_states_missing(&db).await.unwrap());

        threat_source::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(true),
            name: Set("test-feed".to_string()),
            url: Set(
                "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt".to_string(),
            ),
            format: Set("ipsum".to_string()),
            min_score: Set(Some(3)),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        assert!(enabled_threat_source_states_missing(&db).await.unwrap());

        threat_source_state::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            source_name: Set("test-feed".to_string()),
            fingerprint: Set("abc".to_string()),
            prefix_count: Set(1),
            last_checked_at: Set(chrono::Utc::now().naive_utc()),
            last_changed_at: Set(None),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        assert!(!enabled_threat_source_states_missing(&db).await.unwrap());
    }
}
