use super::{
    ApiState, auth, drop_events, dynamic_defense, dynamic_rate_limits, firewall_rules, frontend,
    geo_countries, get_policy_version, health, log_request, nodes, removed_multi_policy_api,
    seed_example_policy, temp_bans, threat_sources, trusted_cidrs,
};
use axum::{
    Router,
    middleware::{self},
    routing::{any, delete, get, post, put},
};

pub(super) fn router(state: ApiState) -> Router {
    let api_routes = api_routes().route_layer(middleware::from_fn_with_state(
        state.clone(),
        auth::require_api_token,
    ));

    Router::new()
        .route("/", get(frontend::index))
        .route("/assets/{*path}", get(frontend::asset))
        .route("/health", get(health))
        .route("/countries", get(super::list_countries))
        .merge(api_routes)
        .fallback(get(frontend::index))
        .with_state(state)
        .layer(middleware::from_fn(log_request))
}

fn api_routes() -> Router<ApiState> {
    Router::new()
        .merge(policy_routes())
        .merge(rule_routes())
        .merge(geo_routes())
        .merge(threat_routes())
        .merge(dynamic_policy_routes())
        .merge(temp_ban_routes())
        .merge(trusted_cidr_routes())
        .merge(node_routes())
        .route("/drop-events/stream", get(drop_events::stream))
}

fn policy_routes() -> Router<ApiState> {
    Router::new()
        .route("/policy/version", get(get_policy_version))
        .route("/policy/bump-version", post(super::bump_policy_version))
        .route("/policy/seed-example", post(seed_example_policy))
        .route("/policies", any(removed_multi_policy_api))
        .route("/policies/{*path}", any(removed_multi_policy_api))
}

fn rule_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/rules",
            get(firewall_rules::list)
                .post(firewall_rules::create)
                .delete(firewall_rules::delete_by_query),
        )
        .route(
            "/rules/batch",
            post(firewall_rules::create_batch).delete(firewall_rules::delete_batch),
        )
        .route("/rules/{id}", delete(firewall_rules::delete_by_id))
}

fn geo_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/geo-countries",
            get(geo_countries::list)
                .post(geo_countries::create)
                .delete(geo_countries::delete_by_query),
        )
        .route(
            "/geo-countries/batch",
            post(geo_countries::create_batch).delete(geo_countries::delete_batch),
        )
        .route("/geo-countries/refresh", post(geo_countries::refresh))
        .route("/geo/lookup", get(geo_countries::lookup))
        .route("/geo-countries/{id}", delete(geo_countries::delete_by_id))
}

fn threat_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/threat-sources",
            get(threat_sources::list)
                .post(threat_sources::create)
                .delete(threat_sources::delete_by_query),
        )
        .route(
            "/threat-sources/batch",
            post(threat_sources::create_batch).delete(threat_sources::delete_batch),
        )
        .route("/threat-sources/refresh", post(threat_sources::refresh))
        .route(
            "/threat-sources/{id}",
            put(threat_sources::update).delete(threat_sources::delete_by_id),
        )
}

fn dynamic_policy_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/dynamic-defense",
            get(dynamic_defense::get).put(dynamic_defense::update),
        )
        .route(
            "/dynamic-rate-limits",
            get(dynamic_rate_limits::list)
                .post(dynamic_rate_limits::create)
                .delete(dynamic_rate_limits::delete_by_query),
        )
        .route(
            "/dynamic-rate-limits/batch",
            post(dynamic_rate_limits::create_batch).delete(dynamic_rate_limits::delete_batch),
        )
        .route(
            "/dynamic-rate-limits/{id}",
            delete(dynamic_rate_limits::delete_by_id),
        )
}

fn temp_ban_routes() -> Router<ApiState> {
    Router::new()
        .route("/temp-bans", get(temp_bans::list).post(temp_bans::create))
        .route(
            "/temp-bans/batch",
            post(temp_bans::create_batch).delete(temp_bans::delete_batch),
        )
        .route("/temp-bans/{id}", delete(temp_bans::delete_by_id))
}

fn trusted_cidr_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/trusted-cidrs",
            get(trusted_cidrs::list)
                .post(trusted_cidrs::create)
                .delete(trusted_cidrs::delete_by_query),
        )
        .route(
            "/trusted-cidrs/batch",
            post(trusted_cidrs::create_batch).delete(trusted_cidrs::delete_batch),
        )
        .route("/trusted-cidrs/{id}", delete(trusted_cidrs::delete_by_id))
}

fn node_routes() -> Router<ApiState> {
    Router::new()
        .route("/nodes", get(nodes::list))
        .route("/nodes/maintenance", post(nodes::maintain))
        .route("/nodes/{node_id}", get(nodes::get))
}
