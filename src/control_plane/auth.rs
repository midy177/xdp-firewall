use anyhow::{Result, bail};
use axum::http::{HeaderMap, header};
use std::net::SocketAddr;

pub const API_TOKEN_ENV: &str = "XDP_FIREWALL_API_TOKEN";
pub const ALLOW_UNAUTHENTICATED_ENV: &str = "XDP_FIREWALL_ALLOW_UNAUTHENTICATED";
const API_TOKEN_HEADER: &str = "x-api-token";

#[must_use]
pub fn api_token_from_env() -> Option<String> {
    std::env::var(API_TOKEN_ENV)
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

#[must_use]
pub fn allow_unauthenticated_from_env() -> bool {
    std::env::var(ALLOW_UNAUTHENTICATED_ENV)
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

pub fn reject_unsafe_unauthenticated_bind(
    bind: SocketAddr,
    api_token: Option<&str>,
    allow_unauthenticated: bool,
) -> Result<()> {
    if api_token.is_none() && !allow_unauthenticated && !bind.ip().is_loopback() {
        bail!(
            "{API_TOKEN_ENV} must be set when the API binds to a non-loopback address; set {ALLOW_UNAUTHENTICATED_ENV}=true only for trusted development networks"
        );
    }
    Ok(())
}

pub fn request_token(headers: &HeaderMap) -> Option<&str> {
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
