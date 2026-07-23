use crate::cli::{ApiArgs, SeedExampleArgs};
use crate::db::entities::{
    dynamic_defense, firewall_rule, geo_country_policy, node, threat_source, trusted_cidr,
};
use crate::{db, firewall, geo, security, threat};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Instant};
use tracing::{error, info, warn};

const API_TOKEN_ENV: &str = "XDP_FIREWALL_API_TOKEN";
const ALLOW_UNAUTHENTICATED_ENV: &str = "XDP_FIREWALL_ALLOW_UNAUTHENTICATED";
const API_TOKEN_HEADER: &str = "x-api-token";
const DEFAULT_PAGE_SIZE: u64 = 100;
const MAX_PAGE_SIZE: u64 = 500;
const FRONTEND_CACHE_CONTROL: &str = "no-store, max-age=0";
const FRONTEND_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

mod frontend_assets {
    include!(concat!(env!("OUT_DIR"), "/frontend_assets.rs"));
}

#[derive(Clone)]
struct ApiState {
    db: DatabaseConnection,
    api_token: Option<String>,
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

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

pub async fn serve(db: DatabaseConnection, args: ApiArgs) -> Result<()> {
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
    let app = router(ApiState { db, api_token });
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
            "/trusted-cidrs",
            get(list_trusted_cidrs).post(create_trusted_cidr),
        )
        .route("/trusted-cidrs/{id}", delete(delete_trusted_cidr))
        .route("/nodes", get(list_nodes))
        .route("/nodes/{node_id}", get(get_node))
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
    } else if status.is_client_error() {
        warn!(%method, %path, status = status.as_u16(), elapsed_ms, "API request rejected");
    } else {
        info!(%method, %path, status = status.as_u16(), elapsed_ms, "API request completed");
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

async fn list_countries() -> Json<&'static [geo::Country]> {
    Json(geo::countries())
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
    validate_cidr(&request.cidr)?;
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
        cidr: Set(request.cidr),
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
    let existing = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(trusted_cidr::Column::Cidr.eq(&cidr))
        .one(&state.db)
        .await?;

    let (status, row) = if let Some(row) = existing {
        let mut active: trusted_cidr::ActiveModel = row.into();
        active.enabled = Set(request.enabled.unwrap_or(true));
        active.comment = Set(request.comment);
        active.updated_at = Set(now);
        (StatusCode::OK, active.update(&state.db).await?)
    } else {
        let row = trusted_cidr::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(request.enabled.unwrap_or(true)),
            cidr: Set(cidr),
            comment: Set(request.comment),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&state.db)
        .await?;
        (StatusCode::CREATED, row)
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

fn validate_cidr(value: &str) -> Result<()> {
    normalize_cidr(value)?;
    Ok(())
}

fn normalize_cidr(value: &str) -> Result<String> {
    let net = value
        .parse::<ipnet::IpNet>()
        .with_context(|| format!("invalid CIDR '{value}'"))?;
    Ok(match net {
        ipnet::IpNet::V4(net) => format!("{}/{}", net.network(), net.prefix_len()),
        ipnet::IpNet::V6(net) => format!("{}/{}", net.network(), net.prefix_len()),
    })
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
        "tcp" | "udp" => Ok(Some(port)),
        "icmp" => bail!("icmp rules cannot set a port"),
        "any" => bail!("port requires protocol tcp or udp"),
        other => bail!("unsupported protocol '{other}'"),
    }
}

fn validate_optional_non_negative(label: &str, value: Option<i32>) -> Result<()> {
    if value.is_some_and(|value| value < 0) {
        bail!("{label} must be greater than or equal to 0");
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
}
