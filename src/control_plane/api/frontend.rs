use super::{ApiError, ApiResult};
use axum::{
    extract::Path,
    http::header,
    response::{IntoResponse, Response},
};

const FRONTEND_CACHE_CONTROL: &str = "no-store, max-age=0";
const FRONTEND_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

mod embedded_assets {
    include!(concat!(env!("OUT_DIR"), "/frontend_assets.rs"));
}

pub(super) async fn index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, FRONTEND_CACHE_CONTROL),
        ],
        embedded_assets::INDEX_HTML,
    )
}

pub(super) async fn asset(Path(path): Path<String>) -> ApiResult<Response> {
    let asset_path = format!("assets/{path}");
    let Some((content_type, body)) = embedded_assets::get(&asset_path) else {
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
