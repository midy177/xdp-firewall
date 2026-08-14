use super::k8s;
use ipnet::IpNet;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::Mutex;
use tracing::warn;

mod compaction;
mod k8s_discovery;
mod snapshot;

pub(in crate::control_plane::xds) use compaction::{
    cidr_fingerprint, compact_covered_cidrs, normalize_runtime_trusted_cidrs,
};
use k8s_discovery::{K8sDiscoveryCache, refresh_k8s_discovery_cache, run_k8s_discovery_watch};
pub(in crate::control_plane::xds) use snapshot::{
    RuntimeTrustedCidrSnapshot, compact_runtime_trusted_cidrs_with_snapshot,
    debug_runtime_trusted_cidrs, inject_runtime_trusted_cidrs,
};

#[derive(Clone)]
pub(in crate::control_plane::xds) struct RuntimeTrustedCidrs {
    pub(in crate::control_plane::xds) configured: Vec<IpNet>,
    pub(in crate::control_plane::xds) k8s_discovery: Option<k8s::KubernetesDiscovery>,
    cache: Arc<Mutex<K8sDiscoveryCache>>,
}

impl RuntimeTrustedCidrs {
    pub(in crate::control_plane::xds) fn new(
        configured: Vec<IpNet>,
        k8s_discovery: Option<k8s::KubernetesDiscovery>,
    ) -> Self {
        Self {
            configured,
            k8s_discovery,
            cache: Arc::new(Mutex::new(K8sDiscoveryCache::default())),
        }
    }

    pub(in crate::control_plane::xds) fn enabled(&self) -> bool {
        !self.configured.is_empty() || self.k8s_discovery.is_some()
    }

    pub(in crate::control_plane::xds) async fn current_snapshot(
        &self,
    ) -> RuntimeTrustedCidrSnapshot {
        let mut cidrs = Vec::new();
        let mut seen = HashSet::new();
        let mut configured = Vec::new();
        for cidr in &self.configured {
            if seen.insert(*cidr) {
                configured.push(*cidr);
                cidrs.push(*cidr);
            }
        }

        if self.k8s_discovery.is_none() {
            let configured = compact_covered_cidrs(&configured);
            return RuntimeTrustedCidrSnapshot {
                all: configured.cidrs.clone(),
                inject: configured.cidrs.clone(),
                configured: configured.cidrs,
                covered: configured.covered,
            };
        }
        let cached = self.cache.lock().await.cidrs.clone();
        for cidr in cached {
            if seen.insert(cidr) {
                cidrs.push(cidr);
            }
        }
        let configured = compact_covered_cidrs(&configured);
        let cidrs = compact_covered_cidrs(&cidrs);
        RuntimeTrustedCidrSnapshot {
            configured: configured.cidrs,
            inject: cidrs.cidrs.clone(),
            all: cidrs.cidrs,
            covered: cidrs.covered,
        }
    }

    pub(in crate::control_plane::xds) async fn initial_refresh(&self) {
        let Some(discovery) = self.k8s_discovery.as_ref() else {
            return;
        };
        if let Err(err) = refresh_k8s_discovery_cache(&self.cache, discovery, "initial").await {
            warn!(
                error = %err,
                "initial Kubernetes runtime address discovery failed; continuing with static runtime trusted CIDRs"
            );
        }
    }

    pub(in crate::control_plane::xds) fn spawn_watch(&self) {
        let Some(discovery) = self.k8s_discovery.clone() else {
            return;
        };
        let cache = self.cache.clone();
        tokio::spawn(async move {
            run_k8s_discovery_watch(cache, discovery).await;
        });
    }
}
