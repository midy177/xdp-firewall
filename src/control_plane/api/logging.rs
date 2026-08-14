use axum::{middleware::Next, response::Response};
use std::time::Instant;
use tracing::{debug, error};

pub(super) async fn log_request(request: axum::extract::Request, next: Next) -> Response {
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
