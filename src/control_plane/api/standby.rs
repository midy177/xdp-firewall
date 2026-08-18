use super::{ApiError, ApiState};
use axum::{
    extract::State,
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};

const READ_ONLY_MESSAGE: &str =
    "server is in standby read-only mode; configuration writes are disabled";

pub(super) async fn reject_writes_in_standby(
    State(state): State<ApiState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if state.standby && is_write_method(request.method()) {
        return ApiError::read_only(READ_ONLY_MESSAGE).into_response();
    }
    next.run(request).await
}

fn is_write_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}
