use super::super::KubernetesWatchOutcome;
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::WatchEvent;
use serde::de::DeserializeOwned;

pub(super) async fn stream_watch_response<T>(
    response: reqwest::Response,
    label: &str,
) -> Result<KubernetesWatchOutcome>
where
    T: DeserializeOwned,
{
    let mut stream = response.bytes_stream();
    let mut pending = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("failed to read Kubernetes watch '{label}'"))?;
        pending.extend_from_slice(&chunk);
        if drain_watch_lines::<T>(&mut pending, label)? {
            return Ok(KubernetesWatchOutcome::Changed);
        }
    }
    if !pending.is_empty() {
        let line = String::from_utf8_lossy(&pending);
        if watch_line_changed::<T>(line.trim(), label)? {
            return Ok(KubernetesWatchOutcome::Changed);
        }
    }
    Ok(KubernetesWatchOutcome::Ended)
}

fn drain_watch_lines<T>(pending: &mut Vec<u8>, label: &str) -> Result<bool>
where
    T: DeserializeOwned,
{
    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
        let line = pending.drain(..=newline).collect::<Vec<_>>();
        let line = String::from_utf8_lossy(&line);
        if watch_line_changed::<T>(line.trim(), label)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(in crate::control_plane::k8s) fn watch_line_changed<T>(line: &str, label: &str) -> Result<bool>
where
    T: DeserializeOwned,
{
    if line.is_empty() {
        return Ok(false);
    }
    let event = serde_json::from_str::<WatchEvent<T>>(line)
        .with_context(|| format!("Kubernetes watch '{label}' returned invalid event JSON"))?;
    match event {
        WatchEvent::Added(_) | WatchEvent::Modified(_) | WatchEvent::Deleted(_) => Ok(true),
        WatchEvent::Bookmark { .. } => Ok(false),
        WatchEvent::ErrorStatus(status) => {
            let message = status
                .message
                .as_deref()
                .unwrap_or("Kubernetes watch error");
            bail!("Kubernetes watch '{label}' returned ERROR event: {message}")
        }
        WatchEvent::ErrorOther(error) => {
            bail!("Kubernetes watch '{label}' returned non-Status ERROR event: {error:?}")
        }
    }
}
