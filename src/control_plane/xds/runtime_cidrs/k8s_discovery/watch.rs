use super::{K8S_WATCH_TIMEOUT, k8s};
use anyhow::{Context, Result, bail};
use tokio::sync::mpsc;
use tracing::{debug, trace};

pub(super) async fn wait_for_k8s_watch_change(
    discovery: k8s::KubernetesDiscovery,
    watch_services: bool,
) -> Result<bool> {
    let (tx, rx) = mpsc::channel(4);
    let mut handles = Vec::new();
    for &(label, path) in k8s_watch_targets(watch_services) {
        let tx = tx.clone();
        let discovery = discovery.clone();
        handles.push(tokio::spawn(async move {
            let result = discovery
                .watch_until_change(path, label, K8S_WATCH_TIMEOUT)
                .await;
            let _ = tx.send((label, result)).await;
        }));
    }
    drop(tx);
    wait_for_watch_outcome(rx, handles).await
}

async fn wait_for_watch_outcome(
    mut rx: mpsc::Receiver<(&'static str, Result<k8s::KubernetesWatchOutcome>)>,
    handles: Vec<tokio::task::JoinHandle<()>>,
) -> Result<bool> {
    let mut unsupported = 0_usize;
    while let Some((label, result)) = rx.recv().await {
        match result {
            Ok(k8s::KubernetesWatchOutcome::Changed) => {
                debug!(
                    label,
                    "Kubernetes watch observed a runtime CIDR source change"
                );
                abort_watch_handles(handles);
                return Ok(true);
            }
            Ok(k8s::KubernetesWatchOutcome::Ended) => {
                trace!(label, "Kubernetes watch stream ended; reconnecting");
                abort_watch_handles(handles);
                return Ok(false);
            }
            Ok(k8s::KubernetesWatchOutcome::Unsupported) => {
                unsupported += 1;
                debug!(label, "Kubernetes watch target is unsupported");
                if unsupported == handles.len() {
                    bail!("all Kubernetes watch targets are unsupported");
                }
            }
            Err(err) => {
                abort_watch_handles(handles);
                return Err(err).with_context(|| format!("Kubernetes watch '{label}' failed"));
            }
        }
    }
    bail!("all Kubernetes watch streams ended without a change notification")
}

fn abort_watch_handles(handles: Vec<tokio::task::JoinHandle<()>>) {
    for handle in handles {
        handle.abort();
    }
}

fn k8s_watch_targets(watch_services: bool) -> &'static [(&'static str, &'static str)] {
    if watch_services {
        &[("nodes", "/api/v1/nodes"), ("services", "/api/v1/services")]
    } else {
        &[
            ("nodes", "/api/v1/nodes"),
            ("servicecidrs", "/apis/networking.k8s.io/v1/servicecidrs"),
        ]
    }
}
