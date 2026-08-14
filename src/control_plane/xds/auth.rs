use super::XdsService;
use anyhow::{Result, bail};
use std::net::SocketAddr;
use tonic::{Status, metadata::MetadataMap};
use tracing::warn;

impl XdsService {
    pub(super) fn authorized(&self, metadata: &MetadataMap) -> bool {
        let Some(expected) = self.agent_token.as_deref() else {
            return true;
        };
        if metadata_token(metadata).is_some_and(|token| constant_time_eq(token, expected)) {
            return true;
        }
        warn!("missing or invalid xDS agent token");
        false
    }
}

pub(super) fn reject_unsafe_unauthenticated_bind(
    bind: SocketAddr,
    agent_token: Option<&str>,
) -> Result<()> {
    if agent_token.is_some()
        || bind.ip().is_loopback()
        || env_flag("XDP_FIREWALL_ALLOW_UNAUTHENTICATED_XDS")
    {
        if agent_token.is_none() {
            warn!(
                %bind,
                "xDS is running without agent token authentication"
            );
        }
        return Ok(());
    }
    bail!(
        "xDS agent token is required when binding xDS to non-loopback address {bind}; set XDP_FIREWALL_AGENT_TOKEN or bind xDS to 127.0.0.1"
    )
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

pub(super) fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..len {
        let l = left.get(index).copied().unwrap_or(0);
        let r = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
}

fn metadata_token(metadata: &MetadataMap) -> Option<&str> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            metadata
                .get("x-agent-token")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

pub(super) fn unauthenticated_status() -> Status {
    Status::unauthenticated("missing or invalid xDS agent token")
}
