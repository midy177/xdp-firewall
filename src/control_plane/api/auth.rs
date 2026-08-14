use super::{ApiError, ApiState};
use axum::{
    extract::State,
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;

pub(super) async fn require_api_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(expected) = state.api_token.as_deref() else {
        return next.run(request).await;
    };
    if crate::control_plane::auth::request_token(&headers).is_some_and(|token| token == expected) {
        return next.run(request).await;
    }
    warn!(
        method = %request.method(),
        path = %request.uri().path(),
        "missing or invalid API token"
    );
    ApiError::unauthorized("missing or invalid API token").into_response()
}
