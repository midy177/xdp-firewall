use crate::cli::{ApiArgs, SeedExampleArgs};
use crate::db::entities::{
    dynamic_defense, dynamic_rate_limit, firewall_rule, geo_country_policy, node, policy_version,
    temp_ban, threat_source, trusted_cidr,
};
use crate::{db, firewall, geo, security, threat, xds};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

const API_TOKEN_ENV: &str = "XDP_FIREWALL_API_TOKEN";
const ALLOW_UNAUTHENTICATED_ENV: &str = "XDP_FIREWALL_ALLOW_UNAUTHENTICATED";
const API_TOKEN_HEADER: &str = "x-api-token";
const DEFAULT_PAGE_SIZE: u64 = 100;
const MAX_PAGE_SIZE: u64 = 500;
const FRONTEND_CACHE_CONTROL: &str = "no-store, max-age=0";
const FRONTEND_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const DEFAULT_TEMP_BAN_SECONDS: i64 = 300;
const MAX_TEMP_BAN_SECONDS: i64 = 31_536_000;
const GEO_REFRESH_RATE_LIMIT: Duration = Duration::from_secs(300);

mod frontend_assets {
    include!(concat!(env!("OUT_DIR"), "/frontend_assets.rs"));
}

#[derive(Clone)]
struct ApiState {
    db: DatabaseConnection,
    api_token: Option<String>,
    drop_events: xds::DropEventHub,
    geo_lookup: geo::GeoIpLookup,
    geo_refresh_limiter: GeoRefreshLimiter,
}

#[derive(Clone, Default)]
struct GeoRefreshLimiter {
    state: Arc<StdMutex<GeoRefreshLimiterState>>,
}

#[derive(Default)]
struct GeoRefreshLimiterState {
    last_started: Option<Instant>,
    running: bool,
    last_result: Option<CachedGeoRefresh>,
}

struct GeoRefreshPermit {
    limiter: GeoRefreshLimiter,
}

#[derive(Clone)]
struct CachedGeoRefresh {
    version: i64,
    report: geo::GeoRefreshReport,
}

enum GeoRefreshDecision {
    Start {
        permit: GeoRefreshPermit,
        previous: Option<CachedGeoRefresh>,
    },
    Running(Option<CachedGeoRefresh>),
    RateLimited(Option<CachedGeoRefresh>),
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct Versioned<T> {
    version: i64,
    data: T,
}

#[derive(Debug, Deserialize)]
struct PaginationQuery {
    page: Option<u64>,
    page_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DropEventQuery {
    node_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeoLookupQuery {
    ip: String,
}

#[derive(Debug, Serialize)]
struct GeoLookupResponse {
    ip: String,
    country: Option<String>,
    country_name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct Pagination {
    page: u64,
    page_size: u64,
}

#[derive(Debug, Serialize)]
struct Page<T> {
    items: Vec<T>,
    total: u64,
    page: u64,
    page_size: u64,
    total_pages: u64,
}

#[derive(Debug, Serialize)]
struct NodeResponse {
    node_id: String,
    interface_name: String,
    last_seen_at: chrono::NaiveDateTime,
    last_applied_version: i64,
    status: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateRuleRequest {
    enabled: Option<bool>,
    priority: i32,
    action: String,
    cidr: String,
    protocol: Option<String>,
    port: Option<i32>,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateGeoCountryRequest {
    enabled: Option<bool>,
    country: String,
    action: String,
}

#[derive(Debug, Deserialize)]
struct CreateThreatSourceRequest {
    enabled: Option<bool>,
    name: String,
    url: String,
    format: String,
    min_score: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CreateTrustedCidrRequest {
    enabled: Option<bool>,
    cidr: String,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateDynamicDefenseRequest {
    enabled: Option<bool>,
    ip_rate_limit_enabled: Option<bool>,
    ip_packets_per_second: Option<i32>,
    ip_burst: Option<i32>,
    flood_enabled: Option<bool>,
    flood_packets_per_second: Option<i32>,
    flood_burst: Option<i32>,
    flood_block_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CreateDynamicRateLimitRequest {
    enabled: Option<bool>,
    priority: i32,
    protocol: String,
    port: Option<i32>,
    packets_per_second: i32,
    burst: i32,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateTempBanRequest {
    ip: String,
    protocol: Option<String>,
    port: Option<i32>,
    duration_seconds: Option<i64>,
    comment: Option<String>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

pub async fn serve(
    db: DatabaseConnection,
    args: ApiArgs,
    drop_events: xds::DropEventHub,
    geo_lookup: geo::GeoIpLookup,
) -> Result<()> {
    let bind = args
        .bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid API bind address '{}'", args.bind))?;
    let api_token = std::env::var(API_TOKEN_ENV)
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let allow_unauthenticated = std::env::var(ALLOW_UNAUTHENTICATED_ENV)
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if api_token.is_none() && !allow_unauthenticated && !bind.ip().is_loopback() {
        bail!(
            "{API_TOKEN_ENV} must be set when the API binds to a non-loopback address; set {ALLOW_UNAUTHENTICATED_ENV}=true only for trusted development networks"
        );
    }
    let auth_enabled = api_token.is_some();
    let app = router(ApiState {
        db,
        api_token,
        drop_events,
        geo_lookup,
        geo_refresh_limiter: GeoRefreshLimiter::default(),
    });
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind API listener on {bind}"))?;
    if allow_unauthenticated {
        warn!(
            %bind,
            auth_enabled,
            "API unauthenticated override is enabled; do not use this on untrusted networks"
        );
    }
    info!(
        %bind,
        auth_enabled,
        allow_unauthenticated,
        "API server listening"
    );
    axum::serve(listener, app)
        .await
        .context("API server failed")
}

fn router(state: ApiState) -> Router {
    let api_routes = Router::new()
        .route("/policy", get(get_policy))
        .route("/policy/bump-version", post(bump_policy_version))
        .route("/policy/seed-example", post(seed_example_policy))
        .route("/policies", any(removed_multi_policy_api))
        .route("/policies/{*path}", any(removed_multi_policy_api))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/{id}", delete(delete_rule))
        .route(
            "/geo-countries",
            get(list_geo_countries).post(create_geo_country),
        )
        .route("/geo-countries/refresh", post(refresh_geo_countries))
        .route("/geo/lookup", get(lookup_geo_ip))
        .route("/geo-countries/{id}", delete(delete_geo_country))
        .route(
            "/threat-sources",
            get(list_threat_sources).post(create_threat_source),
        )
        .route("/threat-sources/{id}", delete(delete_threat_source))
        .route(
            "/dynamic-defense",
            get(get_dynamic_defense).put(update_dynamic_defense),
        )
        .route(
            "/dynamic-rate-limits",
            get(list_dynamic_rate_limits).post(create_dynamic_rate_limit),
        )
        .route(
            "/dynamic-rate-limits/{id}",
            delete(delete_dynamic_rate_limit),
        )
        .route("/temp-bans", get(list_temp_bans).post(create_temp_ban))
        .route("/temp-bans/{id}", delete(delete_temp_ban))
        .route(
            "/trusted-cidrs",
            get(list_trusted_cidrs).post(create_trusted_cidr),
        )
        .route("/trusted-cidrs/{id}", delete(delete_trusted_cidr))
        .route("/nodes", get(list_nodes))
        .route("/nodes/{node_id}", get(get_node))
        .route("/drop-events/stream", get(stream_drop_events))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_token,
        ));

    Router::new()
        .route("/", get(frontend_index))
        .route("/assets/{*path}", get(frontend_asset))
        .route("/health", get(health))
        .route("/countries", get(list_countries))
        .merge(api_routes)
        .fallback(get(frontend_index))
        .with_state(state)
        .layer(middleware::from_fn(log_request))
}

async fn log_request(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started.elapsed().as_millis();
    if status.is_server_error() {
        error!(%method, %path, status = status.as_u16(), elapsed_ms, "API request failed");
    } else {
        debug!(%method, %path, status = status.as_u16(), elapsed_ms, "API request completed");
    }
    response
}

async fn require_api_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(expected) = state.api_token.as_deref() else {
        return next.run(request).await;
    };
    if request_token(&headers).is_some_and(|token| token == expected) {
        return next.run(request).await;
    }
    warn!(
        method = %request.method(),
        path = %request.uri().path(),
        "missing or invalid API token"
    );
    ApiError::unauthorized("missing or invalid API token").into_response()
}

fn request_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get(API_TOKEN_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

async fn frontend_index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, FRONTEND_CACHE_CONTROL),
        ],
        include_str!("../frontend/dist/index.html"),
    )
}

async fn frontend_asset(Path(path): Path<String>) -> ApiResult<Response> {
    let asset_path = format!("assets/{path}");
    let Some((content_type, body)) = frontend_assets::get(&asset_path) else {
        return Err(ApiError::not_found("frontend asset not found"));
    };

    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, FRONTEND_ASSET_CACHE_CONTROL),
        ],
        body,
    )
        .into_response())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn list_countries(State(state): State<ApiState>) -> ApiResult<Json<Vec<geo::CountryOption>>> {
    Ok(Json(geo::list_country_options(&state.db).await?))
}

async fn current_policy_version(db: &DatabaseConnection) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

async fn stream_drop_events(
    Query(query): Query<DropEventQuery>,
    State(state): State<ApiState>,
) -> ApiResult<Response> {
    let node_id = query
        .node_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("all"));
    let mut subscription = state.drop_events.subscribe(node_id);
    let (tx, rx) = mpsc::channel::<std::result::Result<String, Infallible>>(256);
    tokio::spawn(async move {
        loop {
            if tx.is_closed() {
                break;
            }
            tokio::select! {
                event = subscription.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    let Ok(line) = serde_json::to_string(&event) else {
                        continue;
                    };
                    if tx.send(Ok(format!("{line}\n"))).await.is_err() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
        ],
        Body::from_stream(ReceiverStream::new(rx)),
    )
        .into_response())
}

async fn removed_multi_policy_api() -> ApiResult<()> {
    Err(ApiError::not_found(
        "multi-policy API is not supported; use single-policy endpoints",
    ))
}

async fn get_policy(State(state): State<ApiState>) -> ApiResult<Json<firewall::PolicySnapshot>> {
    Ok(Json(
        firewall::load_policy(&state.db, firewall::DEFAULT_POLICY_NAME).await?,
    ))
}

async fn bump_policy_version(
    State(state): State<ApiState>,
) -> ApiResult<Json<Versioned<firewall::PolicySnapshot>>> {
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    let snapshot = firewall::load_policy(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: snapshot,
    }))
}

async fn seed_example_policy(
    State(state): State<ApiState>,
) -> ApiResult<Json<firewall::PolicySnapshot>> {
    firewall::seed_example_policy(&state.db, SeedExampleArgs {}).await?;
    Ok(Json(
        firewall::load_policy(&state.db, firewall::DEFAULT_POLICY_NAME).await?,
    ))
}

async fn list_rules(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<firewall_rule::Model>>> {
    let pagination = query.normalize()?;
    let paginator = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .order_by_asc(firewall_rule::Column::Priority)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_rule(
    State(state): State<ApiState>,
    Json(request): Json<CreateRuleRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<firewall_rule::Model>>)> {
    validate_action(&request.action)?;
    let cidr = normalize_cidr(&request.cidr)?;
    let protocol = request
        .protocol
        .as_deref()
        .map(normalize_protocol)
        .transpose()?;
    let port = validate_port(protocol.as_deref(), request.port)?;
    let row = firewall_rule::ActiveModel {
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(request.enabled.unwrap_or(true)),
        priority: Set(request.priority),
        action: Set(normalize_action(&request.action)?),
        cidr: Set(cidr),
        protocol: Set(protocol),
        port: Set(port),
        comment: Set(request.comment),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&state.db)
    .await?;
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_rule(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(firewall_rule::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("rule not found"));
    }
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_geo_countries(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<geo_country_policy::Model>>> {
    let pagination = query.normalize()?;
    let paginator = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .order_by_asc(geo_country_policy::Column::Country)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_geo_country(
    State(state): State<ApiState>,
    Json(request): Json<CreateGeoCountryRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<geo_country_policy::Model>>)> {
    validate_action(&request.action)?;
    let country = geo::normalize_country(&request.country)?;
    let row = geo_country_policy::ActiveModel {
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(request.enabled.unwrap_or(true)),
        country: Set(country),
        action: Set(normalize_action(&request.action)?),
        packets_per_second: Set(None),
        burst: Set(None),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&state.db)
    .await?;
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn refresh_geo_countries(
    State(state): State<ApiState>,
) -> ApiResult<Json<Versioned<geo::GeoRefreshReport>>> {
    match state
        .geo_refresh_limiter
        .start_or_cached(GEO_REFRESH_RATE_LIMIT)
    {
        GeoRefreshDecision::Start { permit, previous } => {
            let db = state.db.clone();
            let geo_lookup = state.geo_lookup.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match run_geo_refresh(db, geo_lookup).await {
                    Ok(result) => {
                        info!(
                            version = result.version,
                            checked_countries = result.report.checked_country_count,
                            changed_countries = result.report.changed_country_count,
                            prefixes = result.report.prefix_count,
                            "country IP refresh completed"
                        );
                        _permit.finish_success(result);
                    }
                    Err(err) => {
                        warn!(error = %err, "country IP refresh failed");
                    }
                }
            });
            let version = previous
                .as_ref()
                .map(|cached| cached.version)
                .unwrap_or(current_policy_version(&state.db).await?);
            let report = previous
                .map(|cached| geo_refresh_response_report(cached.report, "running", true, true))
                .unwrap_or_else(|| {
                    geo_refresh_response_report(
                        geo::GeoRefreshReport::empty("running"),
                        "running",
                        false,
                        true,
                    )
                });
            Ok(Json(Versioned {
                version,
                data: report,
            }))
        }
        GeoRefreshDecision::Running(cached) => {
            let version = cached
                .as_ref()
                .map(|cached| cached.version)
                .unwrap_or(current_policy_version(&state.db).await?);
            let report = cached
                .map(|cached| geo_refresh_response_report(cached.report, "running", true, true))
                .unwrap_or_else(|| {
                    geo_refresh_response_report(
                        geo::GeoRefreshReport::empty("running"),
                        "running",
                        false,
                        true,
                    )
                });
            Ok(Json(Versioned {
                version,
                data: report,
            }))
        }
        GeoRefreshDecision::RateLimited(cached) => {
            let version = cached
                .as_ref()
                .map(|cached| cached.version)
                .unwrap_or(current_policy_version(&state.db).await?);
            let report = cached
                .map(|cached| {
                    geo_refresh_response_report(cached.report, "rate_limited", true, false)
                })
                .unwrap_or_else(|| {
                    geo_refresh_response_report(
                        geo::GeoRefreshReport::empty("rate_limited"),
                        "rate_limited",
                        false,
                        false,
                    )
                });
            Ok(Json(Versioned {
                version,
                data: report,
            }))
        }
    }
}

async fn lookup_geo_ip(
    State(state): State<ApiState>,
    Query(query): Query<GeoLookupQuery>,
) -> ApiResult<Json<GeoLookupResponse>> {
    let ip: std::net::IpAddr = query.ip.trim().parse().with_context(|| {
        format!(
            "ip must be a valid IPv4 or IPv6 address, got '{}'",
            query.ip.trim()
        )
    })?;
    let country = state.geo_lookup.lookup_country_record(ip);
    debug!(
        ip = %ip,
        hit = country.is_some(),
        country = country.as_ref().map(|country| country.code.as_str()).unwrap_or("-"),
        country_name = country
            .as_ref()
            .and_then(|country| country.name.as_deref())
            .unwrap_or("-"),
        "geo IP lookup completed"
    );
    Ok(Json(GeoLookupResponse {
        ip: ip.to_string(),
        country: country.as_ref().map(|country| country.code.clone()),
        country_name: country.and_then(|country| country.name),
    }))
}

async fn run_geo_refresh(
    db: DatabaseConnection,
    geo_lookup: geo::GeoIpLookup,
) -> Result<CachedGeoRefresh> {
    let mut report = geo::refresh_all_ipdeny_lists(&db).await?;
    let version = if report.changed_country_count > 0 {
        geo_lookup.rebuild_from_db(&db).await?;
        current_policy_version(&db).await?
    } else {
        current_policy_version(&db).await?
    };
    let status = report.refresh_status.clone();
    let running = report.running;
    report = geo_refresh_response_report(report, &status, false, running);
    Ok(CachedGeoRefresh { version, report })
}

fn geo_refresh_response_report(
    mut report: geo::GeoRefreshReport,
    status: &str,
    cached: bool,
    running: bool,
) -> geo::GeoRefreshReport {
    report.refresh_status = status.to_string();
    report.cached = cached;
    report.running = running;
    report
}

async fn delete_geo_country(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("geo country policy not found"));
    }
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_threat_sources(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<threat_source::Model>>> {
    let pagination = query.normalize()?;
    let paginator = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .order_by_asc(threat_source::Column::Name)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_threat_source(
    State(state): State<ApiState>,
    Json(request): Json<CreateThreatSourceRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<threat_source::Model>>)> {
    let format = normalize_threat_format(&request.format)?;
    threat::validate_source_url(&request.url)?;
    validate_optional_non_negative("min_score", request.min_score)?;
    let row = threat_source::ActiveModel {
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(request.enabled.unwrap_or(true)),
        name: Set(request.name),
        url: Set(request.url),
        format: Set(format),
        min_score: Set(request.min_score),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&state.db)
    .await?;
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_threat_source(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("threat source not found"));
    }
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn get_dynamic_defense(
    State(state): State<ApiState>,
) -> ApiResult<Json<firewall::DynamicDefensePolicy>> {
    let data = dynamic_defense::Entity::find_by_id(firewall::DEFAULT_POLICY_NAME.to_string())
        .one(&state.db)
        .await?
        .map(dynamic_defense_policy_from_model)
        .transpose()?
        .unwrap_or_default();
    Ok(Json(data))
}

async fn update_dynamic_defense(
    State(state): State<ApiState>,
    Json(request): Json<UpdateDynamicDefenseRequest>,
) -> ApiResult<Json<Versioned<firewall::DynamicDefensePolicy>>> {
    validate_dynamic_defense_request(&request)?;
    let data = dynamic_defense_policy_from_request(&request)?;
    validate_dynamic_defense_policy(&data)?;
    let now = chrono::Utc::now().naive_utc();
    let existing = dynamic_defense::Entity::find_by_id(firewall::DEFAULT_POLICY_NAME.to_string())
        .one(&state.db)
        .await?;

    if let Some(row) = existing {
        let mut active: dynamic_defense::ActiveModel = row.into();
        active.enabled = Set(data.enabled);
        active.ip_rate_limit_enabled = Set(data.ip_rate_limit_enabled);
        active.ip_packets_per_second = Set(data.ip_packets_per_second.map(|value| value as i32));
        active.ip_burst = Set(data.ip_burst.map(|value| value as i32));
        active.flood_enabled = Set(data.flood_enabled);
        active.flood_packets_per_second =
            Set(data.flood_packets_per_second.map(|value| value as i32));
        active.flood_burst = Set(data.flood_burst.map(|value| value as i32));
        active.flood_block_seconds = Set(data.flood_block_seconds.map(|value| value as i32));
        active.updated_at = Set(now);
        active.update(&state.db).await?;
    } else {
        dynamic_defense::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(data.enabled),
            ip_rate_limit_enabled: Set(data.ip_rate_limit_enabled),
            ip_packets_per_second: Set(data.ip_packets_per_second.map(|value| value as i32)),
            ip_burst: Set(data.ip_burst.map(|value| value as i32)),
            flood_enabled: Set(data.flood_enabled),
            flood_packets_per_second: Set(data.flood_packets_per_second.map(|value| value as i32)),
            flood_burst: Set(data.flood_burst.map(|value| value as i32)),
            flood_block_seconds: Set(data.flood_block_seconds.map(|value| value as i32)),
            updated_at: Set(now),
        }
        .insert(&state.db)
        .await?;
    }

    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned { version, data }))
}

async fn list_dynamic_rate_limits(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<dynamic_rate_limit::Model>>> {
    let pagination = query.normalize()?;
    let paginator = dynamic_rate_limit::Entity::find()
        .filter(dynamic_rate_limit::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .order_by_asc(dynamic_rate_limit::Column::Priority)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_dynamic_rate_limit(
    State(state): State<ApiState>,
    Json(request): Json<CreateDynamicRateLimitRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<dynamic_rate_limit::Model>>)> {
    let protocol = normalize_protocol(&request.protocol)?;
    let port = validate_dynamic_rate_port(protocol.as_str(), request.port)?;
    validate_positive_i32("packets_per_second", request.packets_per_second)?;
    validate_positive_i32("burst", request.burst)?;
    let row = dynamic_rate_limit::ActiveModel {
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(request.enabled.unwrap_or(true)),
        priority: Set(request.priority),
        protocol: Set(protocol),
        port: Set(port),
        packets_per_second: Set(request.packets_per_second),
        burst: Set(request.burst),
        comment: Set(request.comment),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&state.db)
    .await?;
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_dynamic_rate_limit(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = dynamic_rate_limit::Entity::delete_many()
        .filter(dynamic_rate_limit::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(dynamic_rate_limit::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("dynamic rate limit not found"));
    }
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_temp_bans(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<temp_ban::Model>>> {
    let pagination = query.normalize()?;
    let paginator = temp_ban::Entity::find()
        .filter(temp_ban::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(temp_ban::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
        .order_by_asc(temp_ban::Column::ExpiresAt)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_temp_ban(
    State(state): State<ApiState>,
    Json(request): Json<CreateTempBanRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<temp_ban::Model>>)> {
    let ip = normalize_ip(&request.ip)?;
    let protocol = request
        .protocol
        .as_deref()
        .map(normalize_protocol)
        .transpose()?
        .unwrap_or_else(|| "any".to_string());
    let port = validate_dynamic_rate_port(protocol.as_str(), request.port)?;
    let duration_seconds = validate_temp_ban_duration(request.duration_seconds)?;
    let now = chrono::Utc::now().naive_utc();
    let expires_at = now
        .checked_add_signed(chrono::Duration::seconds(duration_seconds))
        .context("temporary ban expiration overflowed")?;
    let row = temp_ban::ActiveModel {
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        ip: Set(ip),
        protocol: Set(protocol),
        port: Set(port),
        expires_at: Set(expires_at),
        comment: Set(request.comment),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&state.db)
    .await?;
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_temp_ban(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = temp_ban::Entity::delete_many()
        .filter(temp_ban::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(temp_ban::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("temporary ban not found"));
    }
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_trusted_cidrs(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<trusted_cidr::Model>>> {
    let pagination = query.normalize()?;
    let paginator = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .order_by_asc(trusted_cidr::Column::Cidr)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_trusted_cidr(
    State(state): State<ApiState>,
    Json(request): Json<CreateTrustedCidrRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<trusted_cidr::Model>>)> {
    let cidr = normalize_cidr(&request.cidr)?;
    let now = chrono::Utc::now().naive_utc();
    let enabled = request.enabled.unwrap_or(true);
    let comment = request.comment;
    let existed = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(trusted_cidr::Column::Cidr.eq(&cidr))
        .one(&state.db)
        .await?
        .is_some();

    trusted_cidr::Entity::insert(trusted_cidr::ActiveModel {
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(enabled),
        cidr: Set(cidr.clone()),
        comment: Set(comment),
        updated_at: Set(now),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::columns([trusted_cidr::Column::PolicyName, trusted_cidr::Column::Cidr])
            .update_columns([
                trusted_cidr::Column::Enabled,
                trusted_cidr::Column::Comment,
                trusted_cidr::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec_without_returning(&state.db)
    .await?;
    let row = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(trusted_cidr::Column::Cidr.eq(&cidr))
        .one(&state.db)
        .await?
        .context("trusted CIDR upsert succeeded but row was not found")?;
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok((status, Json(Versioned { version, data: row })))
}

async fn delete_trusted_cidr(
    State(state): State<ApiState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = trusted_cidr::Entity::delete_many()
        .filter(trusted_cidr::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(trusted_cidr::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("trusted CIDR not found"));
    }
    let version = db::next_policy_version(&state.db, firewall::DEFAULT_POLICY_NAME).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_nodes(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<NodeResponse>>> {
    let pagination = query.normalize()?;
    let paginator = node::Entity::find()
        .order_by_asc(node::Column::NodeId)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator
        .fetch_page(pagination.page - 1)
        .await?
        .into_iter()
        .map(NodeResponse::from)
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

async fn get_node(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
) -> ApiResult<Json<NodeResponse>> {
    let row = node::Entity::find_by_id(node_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("node not found"))?;
    Ok(Json(NodeResponse::from(row)))
}

type ApiResult<T> = std::result::Result<T, ApiError>;

impl PaginationQuery {
    fn normalize(self) -> ApiResult<Pagination> {
        let page = self.page.unwrap_or(1);
        if page == 0 {
            return Err(ApiError::bad_request(
                "page must be greater than or equal to 1",
            ));
        }
        let page_size = self.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if page_size == 0 {
            return Err(ApiError::bad_request(
                "page_size must be greater than or equal to 1",
            ));
        }
        if page_size > MAX_PAGE_SIZE {
            return Err(ApiError::bad_request(format!(
                "page_size must be less than or equal to {MAX_PAGE_SIZE}"
            )));
        }
        Ok(Pagination { page, page_size })
    }
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl<T> Page<T> {
    fn new(items: Vec<T>, total: u64, pagination: Pagination) -> Self {
        Self {
            items,
            total,
            page: pagination.page,
            page_size: pagination.page_size,
            total_pages: total.div_ceil(pagination.page_size),
        }
    }
}

impl From<node::Model> for NodeResponse {
    fn from(value: node::Model) -> Self {
        Self {
            node_id: value.node_id,
            interface_name: value.interface_name,
            last_seen_at: value.last_seen_at,
            last_applied_version: value.last_applied_version,
            status: value.status,
            error: value.error.as_deref().map(security::public_error_message),
        }
    }
}

impl GeoRefreshLimiter {
    fn start_or_cached(&self, interval: Duration) -> GeoRefreshDecision {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .expect("geo refresh limiter mutex poisoned");
        if state.running {
            return GeoRefreshDecision::Running(state.last_result.clone());
        }
        if let Some(last_started) = state.last_started {
            let elapsed = now.saturating_duration_since(last_started);
            if elapsed < interval {
                return GeoRefreshDecision::RateLimited(state.last_result.clone());
            }
        }
        state.running = true;
        state.last_started = Some(now);
        GeoRefreshDecision::Start {
            permit: GeoRefreshPermit {
                limiter: self.clone(),
            },
            previous: state.last_result.clone(),
        }
    }
}

impl GeoRefreshPermit {
    fn finish_success(&self, result: CachedGeoRefresh) {
        let mut state = self
            .limiter
            .state
            .lock()
            .expect("geo refresh limiter mutex poisoned");
        state.last_result = Some(result);
    }
}

impl Drop for GeoRefreshPermit {
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .expect("geo refresh limiter mutex poisoned");
        state.running = false;
    }
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self::bad_request(security::public_error_message(&format!("{value:#}")))
    }
}

impl From<sea_orm::DbErr> for ApiError {
    fn from(value: sea_orm::DbErr) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: security::public_error_message(&value.to_string()),
        }
    }
}

fn normalize_cidr(value: &str) -> Result<String> {
    let cidr = value.trim();
    let net = cidr
        .parse::<ipnet::IpNet>()
        .with_context(|| format!("invalid CIDR '{cidr}'"))?;
    Ok(match net {
        ipnet::IpNet::V4(net) => format!("{}/{}", net.network(), net.prefix_len()),
        ipnet::IpNet::V6(net) => format!("{}/{}", net.network(), net.prefix_len()),
    })
}

fn normalize_ip(value: &str) -> Result<String> {
    let ip = value.trim();
    if ip.contains('/') {
        bail!("source IP must be a single IP address, not CIDR");
    }
    let ip = ip
        .parse::<std::net::IpAddr>()
        .with_context(|| format!("invalid IP address '{ip}'"))?;
    Ok(ip.to_string())
}

fn validate_action(value: &str) -> Result<()> {
    normalize_action(value).map(|_| ())
}

fn normalize_action(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok("allow".to_string()),
        "deny" | "drop" => Ok("deny".to_string()),
        _ => bail!("action must be allow or deny"),
    }
}

fn normalize_protocol(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "any" => Ok("any".to_string()),
        "tcp" => Ok("tcp".to_string()),
        "udp" => Ok("udp".to_string()),
        "icmp" => Ok("icmp".to_string()),
        _ => bail!("protocol must be any, tcp, udp, or icmp"),
    }
}

fn validate_port(protocol: Option<&str>, port: Option<i32>) -> Result<Option<i32>> {
    let Some(port) = port else {
        return Ok(None);
    };
    u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .context("port must be between 1 and 65535")?;
    match protocol.unwrap_or("any") {
        "any" | "tcp" | "udp" => Ok(Some(port)),
        "icmp" => bail!("icmp rules cannot set a port"),
        other => bail!("unsupported protocol '{other}'"),
    }
}

fn validate_dynamic_rate_port(protocol: &str, port: Option<i32>) -> Result<Option<i32>> {
    let Some(port) = port else {
        return Ok(None);
    };
    u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .context("port must be between 1 and 65535")?;
    match protocol {
        "any" | "tcp" | "udp" => Ok(Some(port)),
        "icmp" => bail!("icmp dynamic rate limits cannot set a port"),
        other => bail!("unsupported protocol '{other}'"),
    }
}

fn validate_temp_ban_duration(value: Option<i64>) -> Result<i64> {
    let duration = value.unwrap_or(DEFAULT_TEMP_BAN_SECONDS);
    if duration <= 0 {
        bail!("duration_seconds must be greater than 0");
    }
    if duration > MAX_TEMP_BAN_SECONDS {
        bail!("duration_seconds must be less than or equal to {MAX_TEMP_BAN_SECONDS}");
    }
    Ok(duration)
}

fn validate_optional_non_negative(label: &str, value: Option<i32>) -> Result<()> {
    if value.is_some_and(|value| value < 0) {
        bail!("{label} must be greater than or equal to 0");
    }
    Ok(())
}

fn validate_positive_i32(label: &str, value: i32) -> Result<()> {
    if value <= 0 {
        bail!("{label} must be greater than 0");
    }
    Ok(())
}

fn validate_dynamic_defense_request(request: &UpdateDynamicDefenseRequest) -> Result<()> {
    validate_optional_non_negative("ip_packets_per_second", request.ip_packets_per_second)?;
    validate_optional_non_negative("ip_burst", request.ip_burst)?;
    validate_optional_non_negative("flood_packets_per_second", request.flood_packets_per_second)?;
    validate_optional_non_negative("flood_burst", request.flood_burst)?;
    validate_optional_non_negative("flood_block_seconds", request.flood_block_seconds)?;

    Ok(())
}

fn dynamic_defense_policy_from_request(
    request: &UpdateDynamicDefenseRequest,
) -> Result<firewall::DynamicDefensePolicy> {
    let defaults = firewall::DynamicDefensePolicy::default();
    Ok(firewall::DynamicDefensePolicy {
        enabled: request.enabled.unwrap_or(defaults.enabled),
        ip_rate_limit_enabled: request
            .ip_rate_limit_enabled
            .unwrap_or(defaults.ip_rate_limit_enabled),
        ip_packets_per_second: optional_i32_to_u32(
            "ip_packets_per_second",
            request.ip_packets_per_second,
        )?
        .or(defaults.ip_packets_per_second),
        ip_burst: optional_i32_to_u32("ip_burst", request.ip_burst)?.or(defaults.ip_burst),
        flood_enabled: request.flood_enabled.unwrap_or(defaults.flood_enabled),
        flood_packets_per_second: optional_i32_to_u32(
            "flood_packets_per_second",
            request.flood_packets_per_second,
        )?
        .or(defaults.flood_packets_per_second),
        flood_burst: optional_i32_to_u32("flood_burst", request.flood_burst)?
            .or(defaults.flood_burst),
        flood_block_seconds: optional_i32_to_u32(
            "flood_block_seconds",
            request.flood_block_seconds,
        )?
        .or(defaults.flood_block_seconds),
    })
}

fn optional_i32_to_u32(label: &str, value: Option<i32>) -> Result<Option<u32>> {
    value
        .map(|value| u32::try_from(value).with_context(|| format!("{label} is negative")))
        .transpose()
}

fn validate_dynamic_defense_policy(policy: &firewall::DynamicDefensePolicy) -> Result<()> {
    if policy.enabled && policy.ip_rate_limit_enabled {
        validate_positive("ip_packets_per_second", policy.ip_packets_per_second)?;
        validate_positive("ip_burst", policy.ip_burst)?;
    }
    if policy.enabled && policy.flood_enabled {
        validate_positive("flood_packets_per_second", policy.flood_packets_per_second)?;
        validate_positive("flood_burst", policy.flood_burst)?;
        validate_positive("flood_block_seconds", policy.flood_block_seconds)?;
    }
    Ok(())
}

fn validate_positive(label: &str, value: Option<u32>) -> Result<()> {
    if value.is_some_and(|value| value > 0) {
        return Ok(());
    }
    bail!("{label} must be greater than 0 when enabled")
}

fn dynamic_defense_policy_from_model(
    row: dynamic_defense::Model,
) -> Result<firewall::DynamicDefensePolicy> {
    Ok(firewall::DynamicDefensePolicy {
        enabled: row.enabled,
        ip_rate_limit_enabled: row.ip_rate_limit_enabled,
        ip_packets_per_second: row
            .ip_packets_per_second
            .map(|value| u32::try_from(value).context("ip_packets_per_second is negative"))
            .transpose()?,
        ip_burst: row
            .ip_burst
            .map(|value| u32::try_from(value).context("ip_burst is negative"))
            .transpose()?,
        flood_enabled: row.flood_enabled,
        flood_packets_per_second: row
            .flood_packets_per_second
            .map(|value| u32::try_from(value).context("flood_packets_per_second is negative"))
            .transpose()?,
        flood_burst: row
            .flood_burst
            .map(|value| u32::try_from(value).context("flood_burst is negative"))
            .transpose()?,
        flood_block_seconds: row
            .flood_block_seconds
            .map(|value| u32::try_from(value).context("flood_block_seconds is negative"))
            .transpose()?,
    })
}

fn normalize_threat_format(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "cidr" => Ok("cidr".to_string()),
        "ips" => Ok("ips".to_string()),
        "ipsum" => Ok("ipsum".to_string()),
        "spamhaus_drop" | "spamhaus-drop" => Ok("spamhaus_drop".to_string()),
        _ => bail!("threat format must be cidr, ips, ipsum, or spamhaus_drop"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes,
        http::{Method, Request},
    };
    use sea_orm::{ConnectOptions, Database};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    async fn test_router() -> (Router, DatabaseConnection) {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let db = Database::connect(options).await.unwrap();
        db::migrate(&db).await.unwrap();
        let app = router(ApiState {
            db: db.clone(),
            api_token: None,
            drop_events: xds::DropEventHub::new(),
            geo_lookup: geo::GeoIpLookup::default(),
            geo_refresh_limiter: GeoRefreshLimiter::default(),
        });
        (app, db)
    }

    async fn send_json(app: &Router, method: Method, uri: &str, body: Value) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn send_empty(app: &Router, method: Method, uri: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn response_json(response: Response) -> Value {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(
            status.is_success(),
            "expected success response, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
        serde_json::from_slice(&body).unwrap()
    }

    async fn response_error(response: Response) -> String {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(
            !status.is_success(),
            "expected error response, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
        serde_json::from_slice::<Value>(&body).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn reads_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer secret-token".parse().unwrap(),
        );

        assert_eq!(request_token(&headers), Some("secret-token"));
    }

    #[test]
    fn reads_x_api_token() {
        let mut headers = HeaderMap::new();
        headers.insert(API_TOKEN_HEADER, "secret-token".parse().unwrap());

        assert_eq!(request_token(&headers), Some("secret-token"));
    }

    #[test]
    fn geo_refresh_limiter_returns_cached_result_for_concurrent_and_repeated_refreshes() {
        let limiter = GeoRefreshLimiter::default();
        let permit = match limiter.start_or_cached(Duration::from_secs(300)) {
            GeoRefreshDecision::Start { permit, previous } => {
                assert!(previous.is_none());
                permit
            }
            _ => panic!("first refresh should start"),
        };
        match limiter.start_or_cached(Duration::from_secs(300)) {
            GeoRefreshDecision::Running(None) => {}
            _ => panic!("concurrent refresh without cache should return running state"),
        }

        permit.finish_success(CachedGeoRefresh {
            version: 7,
            report: geo::GeoRefreshReport::empty("completed"),
        });

        drop(permit);
        match limiter.start_or_cached(Duration::from_secs(300)) {
            GeoRefreshDecision::RateLimited(Some(cached)) => assert_eq!(cached.version, 7),
            _ => panic!("repeated refresh should return cached result"),
        }
    }

    #[tokio::test]
    async fn dynamic_defense_update_persists_and_bumps_policy_version() {
        let (app, _db) = test_router().await;
        let update = json!({
            "enabled": true,
            "ip_rate_limit_enabled": true,
            "ip_packets_per_second": 1234,
            "ip_burst": 2345,
            "flood_enabled": true,
            "flood_packets_per_second": 3456,
            "flood_burst": 4567,
            "flood_block_seconds": 89
        });

        let updated =
            response_json(send_json(&app, Method::PUT, "/dynamic-defense", update).await).await;
        assert_eq!(updated["version"], 1);
        assert_eq!(updated["data"]["ip_packets_per_second"], 1234);
        assert_eq!(updated["data"]["flood_block_seconds"], 89);

        let fetched = response_json(send_empty(&app, Method::GET, "/dynamic-defense").await).await;
        assert_eq!(fetched["enabled"], true);
        assert_eq!(fetched["ip_rate_limit_enabled"], true);
        assert_eq!(fetched["ip_packets_per_second"], 1234);
        assert_eq!(fetched["ip_burst"], 2345);
        assert_eq!(fetched["flood_packets_per_second"], 3456);
        assert_eq!(fetched["flood_burst"], 4567);
        assert_eq!(fetched["flood_block_seconds"], 89);
    }

    #[tokio::test]
    async fn dynamic_rate_limit_create_persists_lists_and_loads_policy() {
        let (app, db) = test_router().await;
        let first = json!({
            "enabled": true,
            "priority": 20,
            "protocol": "tcp",
            "port": 443,
            "packets_per_second": 1000,
            "burst": 2000,
            "comment": "https custom limit"
        });
        let second = json!({
            "enabled": true,
            "priority": 10,
            "protocol": "udp",
            "packets_per_second": 3000,
            "burst": 4000,
            "comment": "udp custom limit"
        });

        let created_first =
            response_json(send_json(&app, Method::POST, "/dynamic-rate-limits", first).await).await;
        assert_eq!(created_first["version"], 1);
        assert_eq!(created_first["data"]["protocol"], "tcp");
        assert_eq!(created_first["data"]["port"], 443);

        let created_second =
            response_json(send_json(&app, Method::POST, "/dynamic-rate-limits", second).await)
                .await;
        assert_eq!(created_second["version"], 2);
        assert_eq!(created_second["data"]["protocol"], "udp");
        assert!(created_second["data"]["port"].is_null());

        let page = response_json(
            send_empty(&app, Method::GET, "/dynamic-rate-limits?page=1&page_size=1").await,
        )
        .await;
        assert_eq!(page["total"], 2);
        assert_eq!(page["page"], 1);
        assert_eq!(page["page_size"], 1);
        assert_eq!(page["total_pages"], 2);
        assert_eq!(page["items"][0]["priority"], 10);
        assert_eq!(page["items"][0]["protocol"], "udp");

        let snapshot = firewall::load_policy(&db, firewall::DEFAULT_POLICY_NAME)
            .await
            .unwrap();
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.dynamic_rate_limits.len(), 2);
        assert_eq!(snapshot.dynamic_rate_limits[0].priority, 10);
        assert_eq!(
            snapshot.dynamic_rate_limits[0].protocol,
            firewall::L4Protocol::Udp
        );
        assert_eq!(snapshot.dynamic_rate_limits[0].port, None);
        assert_eq!(snapshot.dynamic_rate_limits[1].priority, 20);
        assert_eq!(
            snapshot.dynamic_rate_limits[1].protocol,
            firewall::L4Protocol::Tcp
        );
        assert_eq!(snapshot.dynamic_rate_limits[1].port, Some(443));
    }

    #[tokio::test]
    async fn rule_create_normalizes_cidr_and_rejects_invalid_ports() {
        let (app, _db) = test_router().await;
        let created = response_json(
            send_json(
                &app,
                Method::POST,
                "/rules",
                json!({
                    "priority": 10,
                    "action": "deny",
                    "cidr": " 203.0.113.42/24 ",
                    "protocol": "tcp",
                    "port": 443
                }),
            )
            .await,
        )
        .await;
        assert_eq!(created["data"]["cidr"], "203.0.113.0/24");

        let any_port_rule = response_json(
            send_json(
                &app,
                Method::POST,
                "/rules",
                json!({
                    "priority": 10,
                    "action": "deny",
                    "cidr": "203.0.113.0/24",
                    "protocol": "any",
                    "port": 443
                }),
            )
            .await,
        )
        .await;
        assert_eq!(any_port_rule["data"]["protocol"], "any");
        assert_eq!(any_port_rule["data"]["port"], 443);

        let range_error = response_error(
            send_json(
                &app,
                Method::POST,
                "/rules",
                json!({
                    "priority": 10,
                    "action": "deny",
                    "cidr": "203.0.113.0/24",
                    "protocol": "tcp",
                    "port": 65536
                }),
            )
            .await,
        )
        .await;
        assert!(range_error.contains("port must be between 1 and 65535"));
    }

    #[tokio::test]
    async fn temporary_ban_rejects_cidr_source_and_invalid_port() {
        let (app, _db) = test_router().await;
        let cidr_error = response_error(
            send_json(
                &app,
                Method::POST,
                "/temp-bans",
                json!({
                    "ip": "203.0.113.0/24",
                    "protocol": "tcp",
                    "port": 443,
                    "duration_seconds": 300
                }),
            )
            .await,
        )
        .await;
        assert!(cidr_error.contains("source IP must be a single IP address"));

        let port_error = response_error(
            send_json(
                &app,
                Method::POST,
                "/temp-bans",
                json!({
                    "ip": "203.0.113.10",
                    "protocol": "tcp",
                    "port": 0,
                    "duration_seconds": 300
                }),
            )
            .await,
        )
        .await;
        assert!(port_error.contains("port must be between 1 and 65535"));
    }

    #[tokio::test]
    async fn dynamic_rate_limit_allows_port_only_limit_and_rejects_icmp_port() {
        let (app, _db) = test_router().await;
        let created = response_json(
            send_json(
                &app,
                Method::POST,
                "/dynamic-rate-limits",
                json!({
                    "enabled": true,
                    "priority": 10,
                    "protocol": "any",
                    "port": 443,
                    "packets_per_second": 1000,
                    "burst": 2000
                }),
            )
            .await,
        )
        .await;
        assert_eq!(created["data"]["protocol"], "any");
        assert_eq!(created["data"]["port"], 443);

        let error = response_error(
            send_json(
                &app,
                Method::POST,
                "/dynamic-rate-limits",
                json!({
                    "enabled": true,
                    "priority": 10,
                    "protocol": "icmp",
                    "port": 443,
                    "packets_per_second": 1000,
                    "burst": 2000
                }),
            )
            .await,
        )
        .await;
        assert!(error.contains("icmp dynamic rate limits cannot set a port"));
    }
}
