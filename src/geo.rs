use crate::db::entities::{geo_country_catalog, geo_ip_list_state, geo_ip_prefix};
use crate::{db, firewall};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use maxminddb::{Mmap, Reader, path};
use mmdb_writer::{IpVersion, Value, Writer};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait, sea_query::OnConflict,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, SeqAccess, Visitor},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt, fs,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tracing::{debug, info, warn};

const IPDENY_ROOT: &str = "https://www.ipdeny.com/ipblocks/";
const IPDENY_AGGREGATED_BASE: &str = "https://www.ipdeny.com/ipblocks/data/aggregated";
const IPDENY_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const IPDENY_INDEX_MAX_BYTES: usize = 2 * 1024 * 1024;
const IPDENY_COUNTRY_MAX_BYTES: usize = 16 * 1024 * 1024;
const REFRESH_LOCK_COUNTRY: &str = "__refresh_lock__";
const REFRESH_LOCK_STALE_SECONDS: i64 = 30 * 60;
const GEOIP_REBUILD_PAGE_SIZE: u64 = 16;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
    pub country: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpdenyMetadata {
    pub country: String,
    pub url: String,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IpdenyCountryPrefixes {
    pub metadata: IpdenyMetadata,
    pub prefixes: Vec<GeoPrefix>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoRefreshReport {
    pub countries: Vec<String>,
    pub checked_country_count: usize,
    pub changed_country_count: usize,
    pub unchanged_country_count: usize,
    pub failed_country_count: usize,
    pub prefix_count: usize,
    pub provider_base_url: &'static str,
    pub refresh_status: String,
    pub cached: bool,
    pub running: bool,
    pub errors: Vec<String>,
}

impl GeoRefreshReport {
    pub fn empty(refresh_status: impl Into<String>) -> Self {
        Self {
            countries: Vec::new(),
            checked_country_count: 0,
            changed_country_count: 0,
            unchanged_country_count: 0,
            failed_country_count: 0,
            prefix_count: 0,
            provider_base_url: IPDENY_ROOT,
            refresh_status: refresh_status.into(),
            cached: false,
            running: false,
            errors: Vec::new(),
        }
    }

    pub fn running() -> Self {
        let mut report = Self::empty("running");
        report.running = true;
        report
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CountryOption {
    pub code: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpdenyIndexEntry {
    pub country: String,
    pub name: String,
    pub url: String,
    pub last_modified: Option<String>,
    pub size_bytes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdbCountryRecord {
    pub country: MmdbCountry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdbCountry {
    pub iso_code: String,
    pub names: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeoIpCountry {
    pub code: String,
    pub name: Option<String>,
}

#[derive(Clone, Default)]
pub struct GeoIpLookup {
    reader: Arc<RwLock<Option<GeoIpDatabase>>>,
}

struct GeoIpDatabase {
    reader: Reader<Mmap>,
    path: PathBuf,
}

#[derive(Debug, Default)]
struct MemorySnapshot {
    memory_limit: Option<String>,
    memory_current: Option<String>,
    vm_rss: Option<String>,
    vm_hwm: Option<String>,
}

impl GeoIpLookup {
    pub async fn rebuild_from_db(&self, db: &DatabaseConnection) -> Result<usize> {
        let country_names = geo_country_catalog::Entity::find()
            .all(db)
            .await?
            .into_iter()
            .map(|row| (row.code, row.name))
            .collect::<HashMap<_, _>>();
        self.clear_reader();

        let mut count = 0_usize;
        let mut skipped_ipv6 = 0_usize;
        let mut writer = Writer::builder("XDP-Firewall-Country")
            .ip_version(IpVersion::V4)
            .build();
        let paginator = geo_ip_prefix::Entity::find()
            .order_by_asc(geo_ip_prefix::Column::Country)
            .paginate(db, GEOIP_REBUILD_PAGE_SIZE);
        let pages = paginator.num_pages().await?;
        for page in 0..pages {
            let rows = paginator.fetch_page(page).await?;
            for row in rows {
                let country = normalize_country(&row.country)?;
                let country_name = country_names
                    .get(&country)
                    .cloned()
                    .unwrap_or_else(|| country.clone());
                let value = mmdb_country_value(&country, &country_name);
                let inserted = match for_each_persisted_cidr(&row, |cidr| {
                    if matches!(cidr, IpNet::V6(_)) {
                        skipped_ipv6 += 1;
                        return Ok(());
                    }
                    writer.insert_value(cidr, value.clone())?;
                    count += 1;
                    Ok(())
                }) {
                    Ok(inserted) => inserted,
                    Err(err) => {
                        warn!(
                            country = %row.country,
                            error = %err,
                            "skipping malformed persisted GeoIP CIDR list while rebuilding MMDB"
                        );
                        continue;
                    }
                };
                debug!(
                    country = %row.country,
                    prefixes = inserted,
                    "added country prefixes to MMDB writer"
                );
            }
        }

        if skipped_ipv6 > 0 {
            warn!(
                skipped_ipv6,
                "skipped IPv6 country prefixes while rebuilding IPv4 IPdeny MMDB"
            );
        }

        if count == 0 {
            return Ok(0);
        }

        let path = geoip_temp_path();
        let bytes = writer.to_bytes()?;
        fs::write(&path, bytes)
            .with_context(|| format!("failed to write temporary MMDB {}", path.display()))?;
        log_geo_memory_snapshot("after temporary MMDB write");
        // SAFETY: the generated file path is unique and is not modified after this mmap is opened.
        let reader = unsafe { Reader::open_mmap(&path) }
            .with_context(|| format!("failed to mmap temporary MMDB {}", path.display()))?;
        *self.reader.write().expect("geoip lookup lock poisoned") =
            Some(GeoIpDatabase { reader, path });
        log_geo_memory_snapshot("after temporary MMDB mmap");
        Ok(count)
    }

    fn clear_reader(&self) {
        let old = self
            .reader
            .write()
            .expect("geoip lookup lock poisoned")
            .take();
        drop(old);
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.lookup_country_record(ip).map(|country| country.code)
    }

    pub fn lookup_country_record(&self, ip: IpAddr) -> Option<GeoIpCountry> {
        let guard = self.reader.read().expect("geoip lookup lock poisoned");
        let database = guard.as_ref()?;
        let result = database.reader.lookup(ip).ok()?;
        let code = result
            .decode_path::<String>(&path!["country", "iso_code"])
            .ok()
            .flatten()?;
        let name = result
            .decode_path::<String>(&path!["country", "names", "en"])
            .ok()
            .flatten();
        Some(GeoIpCountry { code, name })
    }
}

impl Drop for GeoIpDatabase {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            debug!(
                path = %self.path.display(),
                error = %err,
                "failed to remove temporary MMDB"
            );
        }
    }
}

fn geoip_temp_path() -> PathBuf {
    let now = chrono::Utc::now();
    std::env::temp_dir().join(format!(
        "xdp-firewall-geoip-{}-{}.mmdb",
        std::process::id(),
        now.timestamp_nanos_opt()
            .unwrap_or_else(|| now.timestamp_micros() * 1_000)
    ))
}

fn mmdb_country_value(code: &str, name: &str) -> Value {
    Value::map([(
        "country",
        Value::map([
            ("iso_code", Value::from(code)),
            ("names", Value::map([("en", Value::from(name))])),
        ]),
    )])
}

fn log_geo_memory_snapshot(event: &'static str) {
    let snapshot = memory_snapshot();
    debug!(
        event,
        memory_limit = snapshot.memory_limit.as_deref().unwrap_or("-"),
        memory_current = snapshot.memory_current.as_deref().unwrap_or("-"),
        vm_rss = snapshot.vm_rss.as_deref().unwrap_or("-"),
        vm_hwm = snapshot.vm_hwm.as_deref().unwrap_or("-"),
        "GeoIP memory snapshot"
    );
}

fn memory_snapshot() -> MemorySnapshot {
    let mut snapshot = MemorySnapshot {
        memory_limit: read_trimmed("/sys/fs/cgroup/memory.max")
            .or_else(|| read_trimmed("/sys/fs/cgroup/memory/memory.limit_in_bytes")),
        memory_current: read_trimmed("/sys/fs/cgroup/memory.current")
            .or_else(|| read_trimmed("/sys/fs/cgroup/memory/memory.usage_in_bytes")),
        ..Default::default()
    };

    if let Some(status) = read_trimmed("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                snapshot.vm_rss = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("VmHWM:") {
                snapshot.vm_hwm = Some(value.trim().to_string());
            }
        }
    }
    snapshot
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn ipdeny_base_url() -> &'static str {
    IPDENY_AGGREGATED_BASE
}

pub fn ipdeny_country_url(country: &str) -> Result<String> {
    let country = normalize_country(country)?;
    Ok(format!(
        "{IPDENY_AGGREGATED_BASE}/{}-aggregated.zone",
        country.to_ascii_lowercase()
    ))
}

pub async fn refresh_ipdeny_country_catalog(db: &DatabaseConnection) -> Result<Vec<CountryOption>> {
    let client = ipdeny_client()?;
    let body = fetch_text_limited(&client, IPDENY_ROOT, IPDENY_INDEX_MAX_BYTES)
        .await
        .with_context(|| format!("failed to fetch {IPDENY_ROOT}"))?;
    let entries = parse_ipdeny_index(&body)?;
    let now = chrono::Utc::now().naive_utc();
    for entry in &entries {
        geo_country_catalog::Entity::insert(geo_country_catalog::ActiveModel {
            code: Set(entry.country.clone()),
            name: Set(entry.name.clone()),
            url: Set(entry.url.clone()),
            last_modified: Set(entry.last_modified.clone()),
            size_bytes: Set(entry.size_bytes),
            last_checked_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::column(geo_country_catalog::Column::Code)
                .update_columns([
                    geo_country_catalog::Column::Name,
                    geo_country_catalog::Column::Url,
                    geo_country_catalog::Column::LastModified,
                    geo_country_catalog::Column::SizeBytes,
                    geo_country_catalog::Column::LastCheckedAt,
                    geo_country_catalog::Column::UpdatedAt,
                ])
                .to_owned(),
        )
        .exec_without_returning(db)
        .await?;
    }
    list_country_options(db).await
}

pub async fn list_country_options(db: &DatabaseConnection) -> Result<Vec<CountryOption>> {
    Ok(geo_country_catalog::Entity::find()
        .order_by_asc(geo_country_catalog::Column::Code)
        .all(db)
        .await?
        .into_iter()
        .map(|row| CountryOption {
            code: row.code,
            name: row.name,
        })
        .collect())
}

struct GeoRefreshDbLock {
    db: DatabaseConnection,
    owner: String,
}

impl GeoRefreshDbLock {
    async fn try_acquire(db: &DatabaseConnection) -> Result<Option<Self>> {
        let now = chrono::Utc::now().naive_utc();
        let owner = format!(
            "{}:{}",
            std::process::id(),
            now.and_utc()
                .timestamp_nanos_opt()
                .unwrap_or_else(|| now.and_utc().timestamp_micros() * 1_000)
        );
        geo_ip_list_state::Entity::insert(geo_ip_list_state::ActiveModel {
            country: Set(REFRESH_LOCK_COUNTRY.to_string()),
            url: Set(IPDENY_ROOT.to_string()),
            last_modified: Set(Some("idle".to_string())),
            etag: Set(None),
            prefix_count: Set(0),
            last_checked_at: Set(now),
            last_downloaded_at: Set(None),
            updated_at: Set(now),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::column(geo_ip_list_state::Column::Country)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(db)
        .await?;

        let Some(existing) = geo_ip_list_state::Entity::find()
            .filter(geo_ip_list_state::Column::Country.eq(REFRESH_LOCK_COUNTRY))
            .one(db)
            .await?
        else {
            bail!("failed to initialize country IP refresh database lock");
        };

        let is_running = existing.last_modified.as_deref() == Some("running");
        let age_seconds = (now - existing.updated_at).num_seconds();
        if is_running && age_seconds < REFRESH_LOCK_STALE_SECONDS {
            return Ok(None);
        }

        let updated = geo_ip_list_state::Entity::update_many()
            .filter(geo_ip_list_state::Column::Country.eq(REFRESH_LOCK_COUNTRY))
            .filter(geo_ip_list_state::Column::UpdatedAt.eq(existing.updated_at))
            .col_expr(
                geo_ip_list_state::Column::LastModified,
                sea_orm::sea_query::Expr::value("running"),
            )
            .col_expr(
                geo_ip_list_state::Column::Etag,
                sea_orm::sea_query::Expr::value(owner.clone()),
            )
            .col_expr(
                geo_ip_list_state::Column::LastCheckedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .col_expr(
                geo_ip_list_state::Column::UpdatedAt,
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

impl Drop for GeoRefreshDbLock {
    fn drop(&mut self) {
        let db = self.db.clone();
        let owner = self.owner.clone();
        tokio::spawn(async move {
            let now = chrono::Utc::now().naive_utc();
            if let Err(err) = geo_ip_list_state::Entity::update_many()
                .filter(geo_ip_list_state::Column::Country.eq(REFRESH_LOCK_COUNTRY))
                .filter(geo_ip_list_state::Column::Etag.eq(owner))
                .col_expr(
                    geo_ip_list_state::Column::LastModified,
                    sea_orm::sea_query::Expr::value("idle"),
                )
                .col_expr(
                    geo_ip_list_state::Column::Etag,
                    sea_orm::sea_query::Expr::value(Option::<String>::None),
                )
                .col_expr(
                    geo_ip_list_state::Column::UpdatedAt,
                    sea_orm::sea_query::Expr::value(now),
                )
                .exec(&db)
                .await
            {
                warn!(error = %err, "failed to release country IP refresh database lock");
            }
        });
    }
}

pub async fn refresh_ipdeny_lists(
    db: &DatabaseConnection,
    countries: &[String],
) -> Result<GeoRefreshReport> {
    let Some(_guard) = GeoRefreshDbLock::try_acquire(db).await? else {
        return Ok(GeoRefreshReport::running());
    };
    refresh_ipdeny_country_catalog(db).await?;
    let mut requested = BTreeSet::new();
    for country in countries {
        requested.insert(normalize_country(country)?);
    }
    refresh_ipdeny_lists_for_countries(db, requested.into_iter().collect()).await
}

pub async fn refresh_all_ipdeny_lists(db: &DatabaseConnection) -> Result<GeoRefreshReport> {
    let Some(_guard) = GeoRefreshDbLock::try_acquire(db).await? else {
        return Ok(GeoRefreshReport::running());
    };
    let countries = refresh_ipdeny_country_catalog(db)
        .await?
        .into_iter()
        .map(|country| country.code)
        .collect::<Vec<_>>();
    refresh_ipdeny_lists_for_countries(db, countries).await
}

async fn refresh_ipdeny_lists_for_countries(
    db: &DatabaseConnection,
    countries: Vec<String>,
) -> Result<GeoRefreshReport> {
    let mut changed_country_count = 0_usize;
    let mut unchanged_country_count = 0_usize;
    let mut failed_country_count = 0_usize;
    let mut prefix_count = 0_usize;
    let mut errors = Vec::new();
    let client = ipdeny_client()?;
    for country in &countries {
        match refresh_one_country(db, &client, country).await {
            Ok(Some(count)) => {
                changed_country_count += 1;
                prefix_count += count;
            }
            Ok(None) => {
                unchanged_country_count += 1;
            }
            Err(err) => {
                failed_country_count += 1;
                errors.push(format!("{country}: {err:#}"));
                warn!(
                    country,
                    error = %err,
                    "skipping country IP refresh after provider or parsing error"
                );
            }
        }
    }
    Ok(GeoRefreshReport {
        checked_country_count: countries.len(),
        changed_country_count,
        unchanged_country_count,
        failed_country_count,
        countries,
        prefix_count,
        provider_base_url: IPDENY_ROOT,
        refresh_status: if failed_country_count == 0 {
            "completed".to_string()
        } else if changed_country_count > 0 || unchanged_country_count > 0 {
            "partial_failed".to_string()
        } else {
            "failed".to_string()
        },
        cached: false,
        running: false,
        errors,
    })
}

async fn refresh_one_country(
    db: &DatabaseConnection,
    client: &reqwest::Client,
    country: &str,
) -> Result<Option<usize>> {
    let catalog = geo_country_catalog::Entity::find()
        .filter(geo_country_catalog::Column::Code.eq(country))
        .one(db)
        .await?
        .with_context(|| format!("country {country} not found in IPdeny catalog"))?;
    let existing = geo_ip_list_state::Entity::find()
        .filter(geo_ip_list_state::Column::Country.eq(country))
        .one(db)
        .await?;
    let persisted_prefixes = geo_ip_prefix::Entity::find()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .one(db)
        .await?;
    let has_persisted_prefixes = persisted_prefixes
        .as_ref()
        .is_some_and(|row| persisted_cidrs(row).is_ok_and(|cidrs| !cidrs.is_empty()));
    let metadata = fetch_country_metadata(client, country)
        .await
        .unwrap_or_else(|err| {
            warn!(
                country,
                error = %err,
                "failed to fetch country IP metadata; falling back to catalog metadata"
            );
            IpdenyMetadata {
                country: country.to_string(),
                url: catalog.url.clone(),
                last_modified: catalog.last_modified.clone(),
                etag: existing.as_ref().and_then(|row| row.etag.clone()),
            }
        });

    if !geo_ip_list_changed(
        existing.as_ref(),
        has_persisted_prefixes,
        metadata.last_modified.as_deref(),
        metadata.etag.as_deref(),
    ) {
        if let Some(existing) = existing {
            touch_geo_ip_list_state(
                db,
                existing,
                metadata.last_modified.clone(),
                metadata.etag.clone(),
            )
            .await?;
        }
        debug!(country, "country IP list unchanged");
        return Ok(None);
    }

    let fetched = fetch_country_prefixes_streaming(client, country, existing.as_ref()).await?;
    let Some((fetched_metadata, prefixes)) = fetched else {
        if let Some(existing) = existing {
            touch_geo_ip_list_state(
                db,
                existing,
                metadata.last_modified.clone(),
                metadata.etag.clone(),
            )
            .await?;
        }
        debug!(country, "country IP list returned not-modified");
        return Ok(None);
    };
    if prefixes.is_empty() {
        bail!("country {country} IP list is empty");
    }
    let count = prefixes.len();
    let metadata = IpdenyMetadata {
        country: fetched_metadata.country,
        url: fetched_metadata.url,
        last_modified: fetched_metadata.last_modified.or(metadata.last_modified),
        etag: fetched_metadata.etag.or(metadata.etag),
    };
    replace_geo_prefixes(db, &catalog, &metadata, &prefixes).await?;
    info!(country, prefixes = count, "country IP list refreshed");
    Ok(Some(count))
}

pub async fn load_persisted_geo_prefixes(
    db: &DatabaseConnection,
    countries: &[String],
) -> Result<Vec<GeoPrefix>> {
    let mut prefixes = Vec::new();
    for country in countries {
        let country = normalize_country(country)?;
        let country_code = encode_country(&country)?;
        let Some(row) = geo_ip_prefix::Entity::find()
            .filter(geo_ip_prefix::Column::Country.eq(&country))
            .one(db)
            .await?
        else {
            warn!(
                country,
                "enabled country rule has no persisted IP list yet; run /geo-countries/refresh"
            );
            continue;
        };
        let cidrs = match persisted_cidrs(&row) {
            Ok(cidrs) => cidrs,
            Err(err) => {
                warn!(
                    country,
                    error = %err,
                    "skipping malformed persisted country IP list"
                );
                continue;
            }
        };
        for net in cidrs {
            let (addr, prefix) = match net {
                IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
                IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
            };
            prefixes.push(GeoPrefix {
                addr,
                prefix,
                country: country_code,
            });
        }
    }
    Ok(prefixes)
}

pub async fn fetch_ipdeny_metadata(country: &str) -> Result<IpdenyMetadata> {
    let country = normalize_country(country)?;
    let url = ipdeny_country_url(&country)?;
    let response = ipdeny_client()?
        .head(&url)
        .send()
        .await
        .with_context(|| format!("failed to fetch metadata for {url}"))?
        .error_for_status()
        .with_context(|| format!("geo provider returned metadata error for {url}"))?;
    Ok(IpdenyMetadata {
        country,
        url,
        last_modified: header_string(response.headers(), LAST_MODIFIED),
        etag: header_string(response.headers(), ETAG),
    })
}

pub async fn fetch_ipdeny_country_prefixes(country: &str) -> Result<IpdenyCountryPrefixes> {
    let country = normalize_country(country)?;
    let client = ipdeny_client()?;
    let (metadata, prefixes) = fetch_country_prefixes_streaming(&client, &country, None)
        .await?
        .context("geo provider returned not-modified without cached metadata")?;
    Ok(IpdenyCountryPrefixes { prefixes, metadata })
}

fn parse_ipdeny_index(body: &str) -> Result<Vec<IpdenyIndexEntry>> {
    let mut entries = Vec::new();
    let last_modified = parse_ipdeny_root_last_updated(body);
    for line in body.lines() {
        let text = strip_html(line);
        if !text.contains(".zone") {
            continue;
        };
        let Some((name, country)) = parse_ipdeny_country_heading(&text) else {
            continue;
        };
        entries.push(IpdenyIndexEntry {
            url: ipdeny_country_url(&country)?,
            country,
            name,
            last_modified: last_modified.clone(),
            size_bytes: None,
        });
    }
    if entries.is_empty() {
        bail!("IPdeny country block page did not contain country zone files");
    }
    Ok(entries)
}

fn parse_ipdeny_root_last_updated(body: &str) -> Option<String> {
    body.lines().map(strip_html).find_map(|line| {
        line.split_once("Zone files last updated:")
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn parse_ipdeny_country_heading(text: &str) -> Option<(String, String)> {
    let download_index = text.find("[download").or_else(|| text.find(" download "))?;
    let heading = text[..download_index].trim();
    let code_start = heading.rfind('(')?;
    let code_end = heading[code_start..].find(')')? + code_start;
    let code = heading[code_start + 1..code_end].trim();
    if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    let name = heading[..code_start].trim();
    if name.is_empty() {
        return None;
    }
    Some((title_case_country_name(name), code.to_ascii_uppercase()))
}

fn title_case_country_name(name: &str) -> String {
    name.split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            let mut output = String::new();
            output.extend(first.to_uppercase());
            output.push_str(&chars.as_str().to_ascii_lowercase());
            output
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_html(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut in_tag = false;
    for ch in value.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                output.push(' ');
            }
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    output
}

fn geo_ip_list_changed(
    existing: Option<&geo_ip_list_state::Model>,
    has_persisted_prefixes: bool,
    last_modified: Option<&str>,
    etag: Option<&str>,
) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    if !has_persisted_prefixes {
        return true;
    }
    if last_modified.is_none() && etag.is_none() {
        return true;
    }
    existing.last_modified.as_deref() != last_modified || existing.etag.as_deref() != etag
}

async fn replace_geo_prefixes(
    db: &DatabaseConnection,
    catalog: &geo_country_catalog::Model,
    metadata: &IpdenyMetadata,
    prefixes: &[GeoPrefix],
) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let country = catalog.code.clone();
    let url = metadata.url.clone();
    let last_modified = metadata.last_modified.clone();
    let etag = metadata.etag.clone();
    let prefix_count = i32::try_from(prefixes.len()).context("geo prefix count exceeds i32")?;
    let cidrs_json = cidrs_json_from_prefixes(prefixes);
    let cidrs_json_bytes = cidrs_json.len();
    let log_country = country.clone();
    db.transaction::<_, (), sea_orm::DbErr>(|txn| {
        Box::pin(async move {
            geo_ip_prefix::Entity::delete_many()
                .filter(geo_ip_prefix::Column::Country.eq(&country))
                .exec(txn)
                .await?;
            geo_ip_prefix::ActiveModel {
                country: Set(country.clone()),
                cidrs_json: Set(cidrs_json),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(txn)
            .await?;
            geo_ip_list_state::Entity::insert(geo_ip_list_state::ActiveModel {
                country: Set(country.clone()),
                url: Set(url),
                last_modified: Set(last_modified),
                etag: Set(etag),
                prefix_count: Set(prefix_count),
                last_checked_at: Set(now),
                last_downloaded_at: Set(Some(now)),
                updated_at: Set(now),
                ..Default::default()
            })
            .on_conflict(
                OnConflict::column(geo_ip_list_state::Column::Country)
                    .update_columns([
                        geo_ip_list_state::Column::Url,
                        geo_ip_list_state::Column::LastModified,
                        geo_ip_list_state::Column::Etag,
                        geo_ip_list_state::Column::PrefixCount,
                        geo_ip_list_state::Column::LastCheckedAt,
                        geo_ip_list_state::Column::LastDownloadedAt,
                        geo_ip_list_state::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(txn)
            .await?;
            db::next_policy_version_in_transaction(txn, firewall::DEFAULT_POLICY_NAME).await?;
            Ok(())
        })
    })
    .await?;
    let snapshot = memory_snapshot();
    debug!(
        country = %log_country,
        prefixes = prefix_count,
        cidrs_json_bytes,
        memory_limit = snapshot.memory_limit.as_deref().unwrap_or("-"),
        memory_current = snapshot.memory_current.as_deref().unwrap_or("-"),
        vm_rss = snapshot.vm_rss.as_deref().unwrap_or("-"),
        vm_hwm = snapshot.vm_hwm.as_deref().unwrap_or("-"),
        "GeoIP country CIDR list persisted"
    );
    Ok(())
}

async fn touch_geo_ip_list_state(
    db: &DatabaseConnection,
    existing: geo_ip_list_state::Model,
    last_modified: Option<String>,
    etag: Option<String>,
) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let mut active: geo_ip_list_state::ActiveModel = existing.into();
    active.last_modified = Set(last_modified);
    active.etag = Set(etag);
    active.last_checked_at = Set(now);
    active.updated_at = Set(now);
    active.update(db).await?;
    Ok(())
}

fn geo_prefix_to_cidr(prefix: &GeoPrefix) -> String {
    match prefix.addr {
        IpAddr::V4(addr) => format!("{addr}/{}", prefix.prefix),
        IpAddr::V6(addr) => format!("{addr}/{}", prefix.prefix),
    }
}

fn cidrs_json_from_prefixes(prefixes: &[GeoPrefix]) -> String {
    let mut output = String::new();
    output.push('[');
    for (index, prefix) in prefixes.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('"');
        output.push_str(&geo_prefix_to_cidr(prefix));
        output.push('"');
    }
    output.push(']');
    output
}

fn persisted_cidrs(row: &geo_ip_prefix::Model) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();
    for_each_persisted_cidr(row, |cidr| {
        cidrs.push(cidr);
        Ok(())
    })?;
    Ok(cidrs)
}

fn for_each_persisted_cidr<F>(row: &geo_ip_prefix::Model, on_cidr: F) -> Result<usize>
where
    F: FnMut(IpNet) -> Result<()>,
{
    let mut deserializer = serde_json::Deserializer::from_str(&row.cidrs_json);
    deserialize_cidr_array(&mut deserializer, on_cidr)
        .with_context(|| format!("invalid persisted geo CIDR JSON for {}", row.country))
}

fn deserialize_cidr_array<'de, D, F>(
    deserializer: D,
    on_cidr: F,
) -> std::result::Result<usize, D::Error>
where
    D: Deserializer<'de>,
    F: FnMut(IpNet) -> Result<()>,
{
    struct CidrArrayVisitor<F> {
        on_cidr: F,
    }

    impl<'de, F> Visitor<'de> for CidrArrayVisitor<F>
    where
        F: FnMut(IpNet) -> Result<()>,
    {
        type Value = usize;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array of CIDR strings")
        }

        fn visit_seq<A>(mut self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut count = 0_usize;
            while let Some(cidr) = seq.next_element::<IpNet>()? {
                (self.on_cidr)(cidr).map_err(A::Error::custom)?;
                count += 1;
            }
            Ok(count)
        }
    }

    deserializer.deserialize_seq(CidrArrayVisitor { on_cidr })
}

pub async fn fetch_ipdeny_prefixes(countries: &[String]) -> Result<Vec<GeoPrefix>> {
    let mut prefixes = Vec::new();
    for country in countries {
        let country = normalize_country(country)?;
        prefixes.extend(fetch_ipdeny_country_prefixes(&country).await?.prefixes);
    }
    Ok(prefixes)
}

fn parse_ipdeny_line(country: &str, country_code: u16, line: &str) -> Option<GeoPrefix> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let net = match line.parse::<IpNet>() {
        Ok(net) => net,
        Err(err) => {
            warn!(
                country,
                cidr = line,
                error = %err,
                "skipping malformed IPdeny CIDR line"
            );
            return None;
        }
    };
    let (addr, prefix) = match net {
        IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
        IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
    };
    Some(GeoPrefix {
        addr,
        prefix,
        country: country_code,
    })
}

fn header_string(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn ipdeny_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(IPDENY_HTTP_TIMEOUT)
        .build()
        .context("failed to build IPdeny HTTP client")
}

async fn fetch_country_metadata(client: &reqwest::Client, country: &str) -> Result<IpdenyMetadata> {
    let country = normalize_country(country)?;
    let url = ipdeny_country_url(&country)?;
    let response = client
        .head(&url)
        .send()
        .await
        .with_context(|| format!("failed to fetch metadata for {url}"))?
        .error_for_status()
        .with_context(|| format!("geo provider returned metadata error for {url}"))?;
    Ok(IpdenyMetadata {
        country,
        url,
        last_modified: header_string(response.headers(), LAST_MODIFIED),
        etag: header_string(response.headers(), ETAG),
    })
}

async fn fetch_country_prefixes_streaming(
    client: &reqwest::Client,
    country: &str,
    existing: Option<&geo_ip_list_state::Model>,
) -> Result<Option<(IpdenyMetadata, Vec<GeoPrefix>)>> {
    let country = normalize_country(country)?;
    let url = ipdeny_country_url(&country)?;
    let mut request = client.get(&url);
    if let Some(existing) = existing {
        if let Some(etag) = existing.etag.as_deref().filter(|value| !value.is_empty()) {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = existing
            .last_modified
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("failed to fetch {url}"))?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let response = response
        .error_for_status()
        .with_context(|| format!("geo provider returned error for {url}"))?;
    let metadata = IpdenyMetadata {
        country: country.clone(),
        url,
        last_modified: header_string(response.headers(), LAST_MODIFIED),
        etag: header_string(response.headers(), ETAG),
    };
    let country_code = encode_country(&country)?;
    let prefixes = response_lines_limited(response, IPDENY_COUNTRY_MAX_BYTES, |line| {
        Ok(parse_ipdeny_line(&country, country_code, line))
    })
    .await?;
    Ok(Some((metadata, prefixes)))
}

async fn fetch_text_limited(
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
    response_text_limited(response, max_bytes).await
}

async fn response_text_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("geo provider response is too large: content-length exceeds {max_bytes} bytes");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > max_bytes {
            bail!("geo provider response exceeded {max_bytes} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).context("geo provider returned non-UTF-8 response")
}

async fn response_lines_limited<T, F>(
    mut response: reqwest::Response,
    max_bytes: usize,
    mut parse_line: F,
) -> Result<Vec<T>>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("geo provider response is too large: content-length exceeds {max_bytes} bytes");
    }
    let mut total = 0_usize;
    let mut carry = Vec::new();
    let mut parsed = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len();
        if total > max_bytes {
            bail!("geo provider response exceeded {max_bytes} bytes");
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
            let line =
                std::str::from_utf8(&line).context("geo provider returned non-UTF-8 line")?;
            if let Some(value) = parse_line(line)? {
                parsed.push(value);
            }
        }
    }
    if !carry.is_empty() {
        if carry.last() == Some(&b'\r') {
            carry.pop();
        }
        let line = std::str::from_utf8(&carry).context("geo provider returned non-UTF-8 line")?;
        if let Some(value) = parse_line(line)? {
            parsed.push(value);
        }
    }
    Ok(parsed)
}

pub fn normalize_country(value: &str) -> Result<String> {
    let value = value.trim();
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        bail!("invalid ISO country code '{value}'");
    }
    Ok(value.to_ascii_uppercase())
}

pub fn encode_country(value: &str) -> Result<u16> {
    let value = normalize_country(value)?;
    let bytes = value.as_bytes();
    Ok(u16::from(bytes[0]) << 8 | u16::from(bytes[1]))
}

pub fn decode_country(country: u16) -> Result<String> {
    let first = ((country >> 8) & 0xff) as u8;
    let second = (country & 0xff) as u8;
    let code = String::from_utf8(vec![first, second]).context("invalid encoded country")?;
    normalize_country(&code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveModelTrait, ConnectOptions, Database, Set};

    #[test]
    fn parses_ipdeny_country_block_page_entries() {
        let body = r#"
            Zone files last updated: Thu 23 Jul 2026 12:10:16 PM CEST
            CHINA (CN) [download <a href="data/countries/cn.zone">cn.zone</a> ] Size: 133.84 KB (8805 IP blocks)
            [download <a href="data/aggregated/cn-aggregated.zone">cn-aggregrated.zone</a> ] (5507 IP blocks)
            CONGO, THE DEMOCRATIC REPUBLIC OF THE (CD) [download <a href="data/countries/cd.zone">cd.zone</a> ] Size: 1.32 KB (84 IP blocks)
            [download <a href="data/aggregated/cd-aggregated.zone">cd-aggregrated.zone</a> ] (83 IP blocks)
            <a href="Copyrights.txt">Copyrights.txt</a> 03-Dec-2019 03:45 3584
        "#;

        let entries = parse_ipdeny_index(body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].country, "CN");
        assert_eq!(entries[0].name, "China");
        assert_eq!(
            entries[0].last_modified.as_deref(),
            Some("Thu 23 Jul 2026 12:10:16 PM CEST")
        );
        assert_eq!(entries[0].url, ipdeny_country_url("CN").unwrap());
        assert_eq!(entries[1].country, "CD");
        assert_eq!(entries[1].name, "Congo, The Democratic Republic Of The");
    }

    #[test]
    fn geo_ip_list_changed_when_prefix_payload_is_missing() {
        let state = geo_ip_list_state::Model {
            id: 1,
            country: "US".to_string(),
            url: ipdeny_country_url("US").unwrap(),
            last_modified: Some("same".to_string()),
            etag: None,
            prefix_count: 1,
            last_checked_at: chrono::Utc::now().naive_utc(),
            last_downloaded_at: Some(chrono::Utc::now().naive_utc()),
            updated_at: chrono::Utc::now().naive_utc(),
        };
        assert!(geo_ip_list_changed(Some(&state), false, Some("same"), None));
        assert!(!geo_ip_list_changed(Some(&state), true, Some("same"), None));
    }

    #[tokio::test]
    async fn geoip_lookup_rebuilds_from_persisted_prefixes() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();

        geo_country_catalog::ActiveModel {
            code: Set("ZZ".to_string()),
            name: Set("Test Country".to_string()),
            url: Set(ipdeny_country_url("ZZ").unwrap()),
            last_modified: Set(Some("test".to_string())),
            size_bytes: Set(None),
            last_checked_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        geo_ip_prefix::ActiveModel {
            country: Set("ZZ".to_string()),
            cidrs_json: Set(r#"["203.0.113.0/24"]"#.to_string()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let lookup = GeoIpLookup::default();
        assert_eq!(lookup.rebuild_from_db(&db).await.unwrap(), 1);
        assert_eq!(
            lookup.lookup_country("203.0.113.10".parse().unwrap()),
            Some("ZZ".to_string())
        );
        assert_eq!(
            lookup.lookup_country_record("203.0.113.10".parse().unwrap()),
            Some(GeoIpCountry {
                code: "ZZ".to_string(),
                name: Some("Test Country".to_string())
            })
        );
        assert_eq!(
            lookup.lookup_country("198.51.100.10".parse().unwrap()),
            None
        );
    }

    #[tokio::test]
    async fn geoip_lookup_skips_ipv6_prefixes_for_ipdeny_ipv4_database() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();

        geo_country_catalog::ActiveModel {
            code: Set("ZZ".to_string()),
            name: Set("Test Country".to_string()),
            url: Set(ipdeny_country_url("ZZ").unwrap()),
            last_modified: Set(Some("test".to_string())),
            size_bytes: Set(None),
            last_checked_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        geo_ip_prefix::ActiveModel {
            country: Set("ZZ".to_string()),
            cidrs_json: Set(r#"["2001:db8::/32","203.0.113.0/24"]"#.to_string()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let lookup = GeoIpLookup::default();
        assert_eq!(lookup.rebuild_from_db(&db).await.unwrap(), 1);
        assert_eq!(
            lookup.lookup_country("203.0.113.10".parse().unwrap()),
            Some("ZZ".to_string())
        );
        assert_eq!(lookup.lookup_country("2001:db8::1".parse().unwrap()), None);
    }
}
