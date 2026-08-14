use super::super::{K8S_WATCH_CHANGE_DEBOUNCE, K8S_WATCH_RECONNECT_DELAY, K8S_WATCH_TIMEOUT};
use crate::control_plane::k8s;
use anyhow::Result;
use ipnet::IpNet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, trace, warn};

mod watch;

use watch::wait_for_k8s_watch_change;

#[derive(Default)]
pub(super) struct K8sDiscoveryCache {
    pub(super) cidrs: Vec<IpNet>,
    pub(super) initialized: bool,
    service_cidr_partial: bool,
    last_refresh_failed: bool,
}

pub(super) async fn run_k8s_discovery_watch(
    cache: Arc<Mutex<K8sDiscoveryCache>>,
    discovery: k8s::KubernetesDiscovery,
) {
    loop {
        let watch_services = {
            let cache = cache.lock().await;
            cache.service_cidr_partial
        };
        let outcome = wait_for_k8s_watch_change(discovery.clone(), watch_services).await;
        match outcome {
            Ok(true) => {
                if let Err(err) =
                    refresh_k8s_discovery_cache(&cache, &discovery, "watch-change").await
                {
                    mark_k8s_discovery_failed(&cache).await;
                    warn!(
                        error = %err,
                        "Kubernetes runtime address discovery failed after watch event; keeping last cached runtime trusted CIDRs"
                    );
                }
                tokio::time::sleep(K8S_WATCH_CHANGE_DEBOUNCE).await;
            }
            Ok(false) => {}
            Err(err) => {
                mark_k8s_discovery_failed(&cache).await;
                warn!(
                    error = %err,
                    retry_seconds = K8S_WATCH_RECONNECT_DELAY.as_secs(),
                    "Kubernetes watch failed; keeping last cached runtime trusted CIDRs before reconnect"
                );
                tokio::time::sleep(K8S_WATCH_RECONNECT_DELAY).await;
            }
        }
    }
}

pub(super) async fn refresh_k8s_discovery_cache(
    cache: &Arc<Mutex<K8sDiscoveryCache>>,
    discovery: &k8s::KubernetesDiscovery,
    reason: &'static str,
) -> Result<()> {
    let discovered = discovery.discover().await?;
    let mut cache = cache.lock().await;
    let first = !cache.initialized;
    let changed = cache.cidrs != discovered.cidrs;
    let recovered = cache.last_refresh_failed;
    if discovered.service_cidr_partial {
        warn!(
            service_entries = discovered.service_cidrs,
            "Kubernetes ServiceCIDR API is unavailable; using existing Service ClusterIPs as partial runtime whitelist"
        );
    }
    if first || changed || recovered {
        info!(
            reason,
            node_ips = discovered.node_ips,
            pod_cidrs = discovered.pod_cidrs,
            service_cidrs = discovered.service_cidrs,
            service_cidr_partial = discovered.service_cidr_partial,
            total = discovered.cidrs.len(),
            changed,
            recovered,
            "refreshed Kubernetes runtime trusted CIDRs"
        );
    } else {
        trace!(
            reason,
            node_ips = discovered.node_ips,
            pod_cidrs = discovered.pod_cidrs,
            service_cidrs = discovered.service_cidrs,
            service_cidr_partial = discovered.service_cidr_partial,
            total = discovered.cidrs.len(),
            "Kubernetes runtime trusted CIDRs unchanged"
        );
    }
    cache.cidrs = discovered.cidrs;
    cache.initialized = true;
    cache.service_cidr_partial = discovered.service_cidr_partial;
    cache.last_refresh_failed = false;
    Ok(())
}

async fn mark_k8s_discovery_failed(cache: &Arc<Mutex<K8sDiscoveryCache>>) {
    cache.lock().await.last_refresh_failed = true;
}
