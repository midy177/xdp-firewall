use crate::db;
use crate::db::entities::{policy_version, threat_prefix, threat_source, threat_source_state};
use crate::firewall;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use maxminddb::{Mmap, Reader, path};
use mmdb_writer::Value as MmdbValue;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tracing::warn;

const ALLOWED_THREAT_HOSTS_ENV: &str = "XDP_FIREWALL_ALLOWED_THREAT_HOSTS";
const MAX_THREAT_BODY_BYTES: usize = 16 * 1024 * 1024;
const THREAT_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const THREAT_HTTP_MAX_REDIRECTS: usize = 3;
const THREAT_LOOKUP_VERSION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const REFRESH_LOCK_POLICY_NAME: &str = "__threat_refresh_lock__";
const REFRESH_LOCK_SOURCE_NAME: &str = firewall::DEFAULT_POLICY_NAME;
const REFRESH_LOCK_STALE_SECONDS: i64 = 900;
const DEFAULT_ALLOWED_THREAT_HOSTS: &[&str] = &["voipbl.org", "www.voipbl.org"];

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
        min_score: Some(3),
    },
    BuiltinThreatSource {
        name: "voipbl",
        url: "https://voipbl.org/update/",
        format: "voipbl",
        min_score: Some(3),
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatFormat {
    Cidr,
    Ips,
    Ipsum,
    Voipbl,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Clone, Default)]
pub struct ThreatIntelLookup {
    state: Arc<RwLock<ThreatIntelLookupState>>,
}

#[derive(Default)]
struct ThreatIntelLookupState {
    version: Option<i64>,
    last_checked: Option<Instant>,
    rebuild_running: bool,
    database: Option<ThreatIntelDatabase>,
}

struct ThreatIntelDatabase {
    reader: Reader<Mmap>,
    path: PathBuf,
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

impl ThreatFormat {
    fn label(&self) -> &'static str {
        match self {
            ThreatFormat::Cidr => "cidr",
            ThreatFormat::Ips => "ips",
            ThreatFormat::Ipsum => "ipsum",
            ThreatFormat::Voipbl => "voipbl",
            ThreatFormat::SpamhausDrop => "spamhaus_drop",
        }
    }
}

pub async fn fetch_threat_prefixes(sources: &[ThreatSource]) -> Result<Vec<ThreatPrefix>> {
    let mut prefixes = Vec::new();
    let client = threat_http_client()?;
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
    let existing_prefix_sources = threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.source_name)
        .collect::<HashSet<_>>();
    let client = threat_http_client()?;
    let mut states = Vec::with_capacity(sources.len());
    let mut prefixes_by_source = Vec::with_capacity(sources.len());
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
            .is_none_or(|state| state.fingerprint != fingerprint)
            || !existing_prefix_sources.contains(&source.name);
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
        prefixes_by_source.push((source.name.clone(), prefixes));
    }
    let txn = db.begin().await?;
    for (source_name, prefixes) in prefixes_by_source {
        persist_threat_source_prefixes(
            &txn,
            firewall::DEFAULT_POLICY_NAME,
            &source_name,
            &prefixes,
            now,
        )
        .await?;
    }
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

pub async fn load_persisted_threat_prefixes(
    db: &DatabaseConnection,
    policy_name: &str,
    source_names: &[String],
) -> Result<Vec<ThreatPrefix>> {
    if source_names.is_empty() {
        return Ok(Vec::new());
    }
    let rows = threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(policy_name))
        .filter(threat_prefix::Column::SourceName.is_in(source_names.iter().cloned()))
        .order_by_asc(threat_prefix::Column::SourceName)
        .all(db)
        .await?;
    let mut prefixes = Vec::new();
    for row in rows {
        prefixes.extend(persisted_prefixes(&row)?);
    }
    Ok(normalize_prefixes(prefixes))
}

impl ThreatIntelLookup {
    pub async fn lookup_source(&self, db: &DatabaseConnection, ip: IpAddr) -> Option<String> {
        let now = Instant::now();
        let should_check_version = {
            let state = self
                .state
                .read()
                .expect("threat intel lookup lock poisoned");
            state.last_checked.is_none_or(|last| {
                now.saturating_duration_since(last) >= THREAT_LOOKUP_VERSION_CHECK_INTERVAL
            })
        };
        if should_check_version {
            if let Ok(version) = current_policy_version(db).await {
                self.queue_rebuild_for_version(db.clone(), version, Some(now));
            }
        };

        let state = self
            .state
            .read()
            .expect("threat intel lookup lock poisoned");
        let database = state.database.as_ref()?;
        let result = database.reader.lookup(ip).ok()?;
        result
            .decode_path::<String>(&path!["source"])
            .ok()
            .flatten()
    }

    pub fn spawn_rebuild(&self, db: DatabaseConnection) {
        let started = {
            let mut state = self
                .state
                .write()
                .expect("threat intel lookup lock poisoned");
            if state.rebuild_running {
                false
            } else {
                state.rebuild_running = true;
                state.database = None;
                true
            }
        };
        if !started {
            return;
        }
        let lookup = self.clone();
        tokio::spawn(async move {
            let result = async {
                let version = current_policy_version(&db).await?;
                lookup.rebuild_from_db(&db, version).await
            }
            .await;
            lookup.finish_background_rebuild(result);
        });
    }

    fn queue_rebuild_for_version(
        &self,
        db: DatabaseConnection,
        version: i64,
        checked_at: Option<Instant>,
    ) {
        let should_spawn = {
            let mut state = self
                .state
                .write()
                .expect("threat intel lookup lock poisoned");
            if let Some(checked_at) = checked_at {
                state.last_checked = Some(checked_at);
            }
            if state.version == Some(version) || state.rebuild_running {
                false
            } else {
                state.rebuild_running = true;
                state.database = None;
                true
            }
        };
        if !should_spawn {
            return;
        }
        let lookup = self.clone();
        tokio::spawn(async move {
            let result = lookup.rebuild_from_db(&db, version).await;
            lookup.finish_background_rebuild(result);
        });
    }

    fn finish_background_rebuild(&self, result: Result<usize>) {
        let mut state = self
            .state
            .write()
            .expect("threat intel lookup lock poisoned");
        state.rebuild_running = false;
        if let Err(err) = result {
            warn!(error = %err, "failed to rebuild threat intelligence lookup database");
        }
    }

    pub async fn rebuild_from_db(&self, db: &DatabaseConnection, version: i64) -> Result<usize> {
        let enabled_source_names = threat_source::Entity::find()
            .filter(threat_source::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
            .filter(threat_source::Column::Enabled.eq(true))
            .all(db)
            .await?
            .into_iter()
            .map(|row| row.name)
            .collect::<HashSet<_>>();
        if enabled_source_names.is_empty() {
            let mut state = self
                .state
                .write()
                .expect("threat intel lookup lock poisoned");
            state.version = Some(version);
            state.database = None;
            return Ok(0);
        }
        let rows = threat_prefix::Entity::find()
            .filter(threat_prefix::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
            .filter(threat_prefix::Column::SourceName.is_in(enabled_source_names))
            .order_by_asc(threat_prefix::Column::SourceName)
            .all(db)
            .await?;
        let mut sources_by_cidr = BTreeMap::<String, BTreeSet<String>>::new();
        for row in rows {
            for prefix in persisted_prefixes(&row)? {
                sources_by_cidr
                    .entry(prefix_to_cidr(&prefix))
                    .or_default()
                    .insert(row.source_name.clone());
            }
        }

        if sources_by_cidr.is_empty() {
            let mut state = self
                .state
                .write()
                .expect("threat intel lookup lock poisoned");
            state.version = Some(version);
            state.database = None;
            return Ok(0);
        }

        let mut writer = mmdb_writer::Writer::builder("XDP-Firewall-Threat-Intel").build();
        let mut count = 0_usize;
        for (cidr, sources) in sources_by_cidr {
            let net = cidr
                .parse::<IpNet>()
                .with_context(|| format!("invalid persisted threat CIDR '{cidr}'"))?;
            let source = sources.into_iter().collect::<Vec<_>>().join(",");
            writer.insert_value(net, threat_source_value(&source))?;
            count += 1;
        }

        let path = threat_intel_temp_path();
        {
            let file = fs::File::create(&path).with_context(|| {
                format!("failed to create temporary threat MMDB {}", path.display())
            })?;
            let mut file = std::io::BufWriter::new(file);
            writer.write_to(&mut file).with_context(|| {
                format!("failed to write temporary threat MMDB {}", path.display())
            })?;
            file.flush().with_context(|| {
                format!("failed to flush temporary threat MMDB {}", path.display())
            })?;
        }
        drop(writer);

        // SAFETY: the generated file path is unique and is not modified after this mmap is opened.
        let reader = unsafe { Reader::open_mmap(&path) }
            .with_context(|| format!("failed to mmap temporary threat MMDB {}", path.display()))?;
        let mut state = self
            .state
            .write()
            .expect("threat intel lookup lock poisoned");
        state.version = Some(version);
        state.database = Some(ThreatIntelDatabase { reader, path });
        Ok(count)
    }
}

impl Drop for ThreatIntelDatabase {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            warn!(
                path = %self.path.display(),
                error = %err,
                "failed to remove temporary threat MMDB"
            );
        }
    }
}

pub async fn delete_persisted_threat_prefixes_by_name<'a, I>(
    db: &impl ConnectionTrait,
    names: I,
) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let names = names.into_iter().collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(());
    }
    threat_prefix::Entity::delete_many()
        .filter(threat_prefix::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(threat_prefix::Column::SourceName.is_in(names))
        .exec(db)
        .await?;
    Ok(())
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
            .filter(threat_source_state::Column::SourceName.eq(source.name.clone()))
            .one(db)
            .await?
            .is_some();
        if !has_state {
            return Ok(true);
        }
        let has_prefixes = threat_prefix::Entity::find()
            .filter(threat_prefix::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
            .filter(threat_prefix::Column::SourceName.eq(source.name))
            .one(db)
            .await?
            .is_some();
        if !has_prefixes {
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
                parse_lenient_line_prefix(line, source.format.label())
            })
            .await
        }
        ThreatFormat::Voipbl => {
            read_limited_lines(response, MAX_THREAT_BODY_BYTES, |line| {
                parse_lenient_line_prefix(line, source.format.label())
            })
            .await
        }
        ThreatFormat::Ipsum => {
            let min_score = source.min_score.unwrap_or(1);
            read_limited_lines(response, MAX_THREAT_BODY_BYTES, |line| {
                parse_lenient_ipsum_line(line, min_score)
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

fn threat_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(THREAT_HTTP_TIMEOUT)
        .redirect(threat_redirect_policy())
        .build()
        .context("failed to build threat HTTP client")
}

fn threat_redirect_policy() -> reqwest::redirect::Policy {
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
                format!("threat source redirect target is not allowed: {err}"),
            ));
        }
        attempt.follow()
    })
}

pub fn validate_source_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("invalid threat source URL '{value}'"))?;
    validate_source_url_parts(&url)
}

fn validate_source_url_parts(url: &reqwest::Url) -> Result<()> {
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
    hosts.extend(
        DEFAULT_ALLOWED_THREAT_HOSTS
            .iter()
            .map(|host| host.to_ascii_lowercase()),
    );
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

fn parse_lenient_line_prefix(line: &str, format: &str) -> Result<Option<ThreatPrefix>> {
    let Some(token) = first_prefix_token(line) else {
        return Ok(None);
    };
    match parse_prefix(token) {
        Ok(prefix) => Ok(Some(prefix)),
        Err(err) => {
            warn!(format, line = line.trim(), error = %err, "skipping invalid threat line");
            Ok(None)
        }
    }
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

fn parse_lenient_ipsum_line(line: &str, min_score: u32) -> Result<Option<ThreatPrefix>> {
    match parse_ipsum_line(line, min_score) {
        Ok(prefix) => Ok(prefix),
        Err(err) => {
            warn!(format = "ipsum", line = line.trim(), error = %err, "skipping invalid threat line");
            Ok(None)
        }
    }
}

fn parse_spamhaus_drop(body: &str) -> Result<Vec<ThreatPrefix>> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        let mut prefixes = Vec::new();
        collect_json_cidrs(&value, &mut prefixes)?;
        if !prefixes.is_empty() {
            return Ok(prefixes);
        }
    }
    let mut prefixes = Vec::new();
    for line in body.lines() {
        if let Some(prefix) = parse_lenient_line_prefix(line, "spamhaus_drop")? {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
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
                match parse_prefix(cidr) {
                    Ok(prefix) => prefixes.push(prefix),
                    Err(err) => {
                        warn!(format = "spamhaus_drop", cidr, error = %err, "skipping invalid threat CIDR");
                    }
                }
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

async fn persist_threat_source_prefixes(
    db: &impl ConnectionTrait,
    policy_name: &str,
    source_name: &str,
    prefixes: &[ThreatPrefix],
    now: chrono::NaiveDateTime,
) -> Result<()> {
    let cidrs_json = cidrs_json_from_prefixes(prefixes);
    threat_prefix::Entity::delete_many()
        .filter(threat_prefix::Column::PolicyName.eq(policy_name))
        .filter(threat_prefix::Column::SourceName.eq(source_name))
        .exec(db)
        .await?;
    threat_prefix::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        source_name: Set(source_name.to_string()),
        cidrs_json: Set(cidrs_json),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}

fn cidrs_json_from_prefixes(prefixes: &[ThreatPrefix]) -> String {
    let cidrs = prefixes.iter().map(prefix_to_cidr).collect::<Vec<_>>();
    serde_json::to_string(&cidrs).expect("threat CIDR list should serialize")
}

fn persisted_prefixes(row: &threat_prefix::Model) -> Result<Vec<ThreatPrefix>> {
    let cidrs = serde_json::from_str::<Vec<String>>(&row.cidrs_json)
        .with_context(|| format!("invalid persisted threat CIDR list for {}", row.source_name))?;
    cidrs
        .iter()
        .map(|cidr| parse_prefix(cidr))
        .collect::<Result<Vec<_>>>()
}

fn prefix_to_cidr(prefix: &ThreatPrefix) -> String {
    match prefix.addr {
        IpAddr::V4(addr) => format!("{addr}/{}", prefix.prefix),
        IpAddr::V6(addr) => format!("{addr}/{}", prefix.prefix),
    }
}

async fn current_policy_version(db: &DatabaseConnection) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

fn threat_source_value(source: &str) -> MmdbValue {
    MmdbValue::map([("source", MmdbValue::from(source))])
}

fn threat_intel_temp_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "xdp-firewall-threat-{}-{}.mmdb",
        std::process::id(),
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp_micros() * 1_000)
    ))
}

fn parse_format(value: &str) -> Result<ThreatFormat> {
    match value.to_ascii_lowercase().as_str() {
        "cidr" => Ok(ThreatFormat::Cidr),
        "ips" => Ok(ThreatFormat::Ips),
        "ipsum" => Ok(ThreatFormat::Ipsum),
        "voipbl" | "voipbl_cidr" | "voipbl-cidr" => Ok(ThreatFormat::Voipbl),
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
    fn builtin_sources_include_default_feeds() {
        assert_eq!(
            BUILTIN_THREAT_SOURCES
                .iter()
                .map(|source| source.name)
                .collect::<Vec<_>>(),
            ["ipsum", "spamhaus-drop", "voipbl"]
        );
        assert_eq!(BUILTIN_THREAT_SOURCES[0].min_score, Some(3));
        assert_eq!(BUILTIN_THREAT_SOURCES[1].format, "spamhaus_drop");
        assert_eq!(BUILTIN_THREAT_SOURCES[2].format, "voipbl");
        assert_eq!(BUILTIN_THREAT_SOURCES[2].url, "https://voipbl.org/update/");
    }

    #[test]
    fn rejects_threat_url_credentials() {
        let err = validate_source_url("https://user:secret@raw.githubusercontent.com/feed.txt")
            .unwrap_err();
        assert!(err.to_string().contains("must not contain credentials"));
    }

    #[test]
    fn accepts_voipbl_source_url_by_default() {
        validate_source_url("https://voipbl.org/update/").unwrap();
        validate_source_url("http://www.voipbl.org/update/").unwrap();
    }

    #[tokio::test]
    async fn follows_allowed_307_threat_source_redirects() {
        use axum::{
            Router,
            http::{StatusCode, header},
            routing::get,
        };
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let location = format!("http://voipbl.org:{port}/feed");
        let app = Router::new()
            .route(
                "/start",
                get(move || async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, location)],
                    )
                }),
            )
            .route("/feed", get(|| async { "198.51.100.0/24\n" }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder()
            .timeout(THREAT_HTTP_TIMEOUT)
            .redirect(threat_redirect_policy())
            .resolve("voipbl.org", SocketAddr::from(([127, 0, 0, 1], port)))
            .build()
            .unwrap();
        let prefixes = fetch_threat_source_prefixes(
            &client,
            &ThreatSource {
                name: "voipbl".to_string(),
                url: format!("http://voipbl.org:{port}/start"),
                format: ThreatFormat::Voipbl,
                min_score: Some(3),
            },
        )
        .await
        .unwrap();

        server.abort();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(
            prefixes[0],
            ThreatPrefix {
                addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 24,
            }
        );
    }

    #[test]
    fn parses_voipbl_cidr_lines() {
        let mut prefixes = Vec::new();
        for line in "# TOTAL NETBLOCK: 2\n\
             23.16.0.0/15\n\
             137.184.10/32\n\
             23.29.192.0/19\n"
            .lines()
        {
            if let Some(prefix) = parse_lenient_line_prefix(line, "voipbl").unwrap() {
                prefixes.push(prefix);
            }
        }
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].prefix, 15);
    }

    #[test]
    fn lenient_line_formats_skip_invalid_cidrs() {
        assert!(
            parse_lenient_line_prefix("137.184.10/32", "cidr")
                .unwrap()
                .is_none()
        );
        assert!(
            parse_lenient_line_prefix("198.51.100.0/24", "cidr")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn lenient_ipsum_skips_invalid_scored_ip() {
        assert!(
            parse_lenient_ipsum_line("137.184.10 5", 3)
                .unwrap()
                .is_none()
        );
        assert!(
            parse_lenient_ipsum_line("198.51.100.1 5", 3)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn spamhaus_drop_skips_invalid_json_cidrs() {
        let prefixes = parse_spamhaus_drop(
            r#"[
                {"cidr":"137.184.10/32"},
                {"cidr":"198.51.100.0/24"}
            ]"#,
        )
        .unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix, 24);
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
        assert!(enabled_threat_source_states_missing(&db).await.unwrap());

        threat_prefix::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            source_name: Set("test-feed".to_string()),
            cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        assert!(!enabled_threat_source_states_missing(&db).await.unwrap());
    }

    #[tokio::test]
    async fn threat_intel_lookup_rebuilds_from_persisted_prefixes() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        let now = chrono::Utc::now().naive_utc();

        for name in ["feed-a", "feed-b"] {
            threat_source::ActiveModel {
                policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
                enabled: Set(true),
                name: Set(name.to_string()),
                url: Set(format!("https://example.com/{name}.txt")),
                format: Set("cidr".to_string()),
                min_score: Set(None),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(&db)
            .await
            .unwrap();
        }
        threat_prefix::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            source_name: Set("feed-a".to_string()),
            cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        threat_prefix::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            source_name: Set("feed-b".to_string()),
            cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        let version = db::next_policy_version(&db, firewall::DEFAULT_POLICY_NAME)
            .await
            .unwrap();

        let lookup = ThreatIntelLookup::default();
        lookup.rebuild_from_db(&db, version).await.unwrap();
        assert_eq!(
            lookup
                .lookup_source(&db, "198.51.100.10".parse().unwrap())
                .await,
            Some("feed-a,feed-b".to_string())
        );
        assert_eq!(
            lookup
                .lookup_source(&db, "203.0.113.10".parse().unwrap())
                .await,
            None
        );
    }

    #[tokio::test]
    async fn threat_intel_lookup_ignores_disabled_sources() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        let now = chrono::Utc::now().naive_utc();

        for (name, enabled) in [("enabled-feed", true), ("disabled-feed", false)] {
            threat_source::ActiveModel {
                policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
                enabled: Set(enabled),
                name: Set(name.to_string()),
                url: Set(format!("https://example.com/{name}.txt")),
                format: Set("cidr".to_string()),
                min_score: Set(None),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(&db)
            .await
            .unwrap();
            threat_prefix::ActiveModel {
                policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
                source_name: Set(name.to_string()),
                cidrs_json: Set(if enabled {
                    r#"["198.51.100.0/24"]"#.to_string()
                } else {
                    r#"["203.0.113.0/24"]"#.to_string()
                }),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(&db)
            .await
            .unwrap();
        }

        let lookup = ThreatIntelLookup::default();
        let version = db::next_policy_version(&db, firewall::DEFAULT_POLICY_NAME)
            .await
            .unwrap();
        lookup.rebuild_from_db(&db, version).await.unwrap();
        assert_eq!(
            lookup
                .lookup_source(&db, "198.51.100.10".parse().unwrap())
                .await,
            Some("enabled-feed".to_string())
        );
        assert_eq!(
            lookup
                .lookup_source(&db, "203.0.113.10".parse().unwrap())
                .await,
            None
        );
    }
}
