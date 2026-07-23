use crate::cli::{ApiArgs, SeedExampleArgs};
use crate::db::entities::{firewall_rule, geo_country_policy, node, policy_version, threat_source};
use crate::{db, firewall, geo, security, threat};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;

const API_TOKEN_ENV: &str = "XDP_FIREWALL_API_TOKEN";
const ALLOW_UNAUTHENTICATED_ENV: &str = "XDP_FIREWALL_ALLOW_UNAUTHENTICATED";
const API_TOKEN_HEADER: &str = "x-api-token";
const DEFAULT_PAGE_SIZE: u64 = 100;
const MAX_PAGE_SIZE: u64 = 500;

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
    policy_name: String,
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
    packets_per_second: Option<i32>,
    burst: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CreateThreatSourceRequest {
    enabled: Option<bool>,
    name: String,
    url: String,
    format: String,
    min_score: Option<i32>,
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
    info!(%bind, auth_enabled, "API server listening");
    axum::serve(listener, app)
        .await
        .context("API server failed")
}

fn router(state: ApiState) -> Router {
    let api_routes = Router::new()
        .route("/policies", get(list_policies))
        .route("/policies/{policy}", get(get_policy))
        .route("/policies/{policy}/bump-version", post(bump_policy_version))
        .route("/policies/{policy}/seed-example", post(seed_example_policy))
        .route(
            "/policies/{policy}/rules",
            get(list_rules).post(create_rule),
        )
        .route("/policies/{policy}/rules/{id}", delete(delete_rule))
        .route(
            "/policies/{policy}/geo-countries",
            get(list_geo_countries).post(create_geo_country),
        )
        .route(
            "/policies/{policy}/geo-countries/{id}",
            delete(delete_geo_country),
        )
        .route(
            "/policies/{policy}/threat-sources",
            get(list_threat_sources).post(create_threat_source),
        )
        .route(
            "/policies/{policy}/threat-sources/{id}",
            delete(delete_threat_source),
        )
        .route("/nodes", get(list_nodes))
        .route("/nodes/{node_id}", get(get_node))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_token,
        ));

    Router::new()
        .route("/", get(frontend_index))
        .route("/assets/index.js", get(frontend_js))
        .route("/assets/index.css", get(frontend_css))
        .route("/health", get(health))
        .merge(api_routes)
        .fallback(get(frontend_index))
        .with_state(state)
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
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../frontend/dist/index.html"),
    )
}

async fn frontend_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../frontend/dist/assets/index.js"),
    )
}

async fn frontend_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../frontend/dist/assets/index.css"),
    )
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn list_policies(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<policy_version::Model>>> {
    let pagination = query.normalize()?;
    let paginator = policy_version::Entity::find()
        .order_by_asc(policy_version::Column::PolicyName)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn get_policy(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
) -> ApiResult<Json<firewall::PolicySnapshot>> {
    Ok(Json(firewall::load_policy(&state.db, &policy).await?))
}

async fn bump_policy_version(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
) -> ApiResult<Json<Versioned<firewall::PolicySnapshot>>> {
    let version = db::next_policy_version(&state.db, &policy).await?;
    let snapshot = firewall::load_policy(&state.db, &policy).await?;
    Ok(Json(Versioned {
        version,
        data: snapshot,
    }))
}

async fn seed_example_policy(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
) -> ApiResult<Json<firewall::PolicySnapshot>> {
    firewall::seed_example_policy(
        &state.db,
        SeedExampleArgs {
            name: policy.clone(),
        },
    )
    .await?;
    Ok(Json(firewall::load_policy(&state.db, &policy).await?))
}

async fn list_rules(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<firewall_rule::Model>>> {
    let pagination = query.normalize()?;
    let paginator = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(policy))
        .order_by_asc(firewall_rule::Column::Priority)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_rule(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
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
        policy_name: Set(policy.clone()),
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
    let version = db::next_policy_version(&state.db, &policy).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_rule(
    State(state): State<ApiState>,
    Path((policy, id)): Path<(String, i32)>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(&policy))
        .filter(firewall_rule::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("rule not found"));
    }
    let version = db::next_policy_version(&state.db, &policy).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_geo_countries(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<geo_country_policy::Model>>> {
    let pagination = query.normalize()?;
    let paginator = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(policy))
        .order_by_asc(geo_country_policy::Column::Country)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_geo_country(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
    Json(request): Json<CreateGeoCountryRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<geo_country_policy::Model>>)> {
    validate_action(&request.action)?;
    let country = geo::normalize_country(&request.country)?;
    validate_optional_non_negative("packets_per_second", request.packets_per_second)?;
    validate_optional_non_negative("burst", request.burst)?;
    let row = geo_country_policy::ActiveModel {
        policy_name: Set(policy.clone()),
        enabled: Set(request.enabled.unwrap_or(true)),
        country: Set(country),
        action: Set(normalize_action(&request.action)?),
        packets_per_second: Set(request.packets_per_second),
        burst: Set(request.burst),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&state.db)
    .await?;
    let version = db::next_policy_version(&state.db, &policy).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_geo_country(
    State(state): State<ApiState>,
    Path((policy, id)): Path<(String, i32)>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(&policy))
        .filter(geo_country_policy::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("geo country policy not found"));
    }
    let version = db::next_policy_version(&state.db, &policy).await?;
    Ok(Json(Versioned {
        version,
        data: serde_json::json!({ "deleted": id }),
    }))
}

async fn list_threat_sources(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<threat_source::Model>>> {
    let pagination = query.normalize()?;
    let paginator = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(policy))
        .order_by_asc(threat_source::Column::Name)
        .paginate(&state.db, pagination.page_size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.page - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

async fn create_threat_source(
    State(state): State<ApiState>,
    Path(policy): Path<String>,
    Json(request): Json<CreateThreatSourceRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<threat_source::Model>>)> {
    let format = normalize_threat_format(&request.format)?;
    threat::validate_source_url(&request.url)?;
    validate_optional_non_negative("min_score", request.min_score)?;
    let row = threat_source::ActiveModel {
        policy_name: Set(policy.clone()),
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
    let version = db::next_policy_version(&state.db, &policy).await?;
    Ok((StatusCode::CREATED, Json(Versioned { version, data: row })))
}

async fn delete_threat_source(
    State(state): State<ApiState>,
    Path((policy, id)): Path<(String, i32)>,
) -> ApiResult<Json<Versioned<serde_json::Value>>> {
    let deleted = threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(&policy))
        .filter(threat_source::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("threat source not found"));
    }
    let version = db::next_policy_version(&state.db, &policy).await?;
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
            policy_name: value.policy_name,
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
    value
        .parse::<ipnet::IpNet>()
        .with_context(|| format!("invalid CIDR '{value}'"))?;
    Ok(())
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
