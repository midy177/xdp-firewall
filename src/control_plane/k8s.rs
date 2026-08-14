use anyhow::Result;
use ipnet::IpNet;
use k8s_openapi::api::{
    core::v1::{Node, Service},
    networking::v1::ServiceCIDR,
};
use std::collections::HashSet;
use tracing::{trace, warn};

mod cidrs;
mod client;
mod config;
mod watch;

#[cfg(test)]
mod tests;

use cidrs::{add_node_runtime_cidrs, add_service_cidrs, add_service_cluster_ips};
use client::is_forbidden_error;

#[derive(Debug, Clone)]
pub struct KubernetesDiscovery {
    client: reqwest::Client,
    api_server: String,
    token: String,
}

#[derive(Debug, Clone, Default)]
pub struct KubernetesRuntimeCidrs {
    pub cidrs: Vec<IpNet>,
    pub node_ips: usize,
    pub pod_cidrs: usize,
    pub service_cidrs: usize,
    pub service_cidr_partial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KubernetesWatchOutcome {
    Changed,
    Ended,
    Unsupported,
}

impl KubernetesDiscovery {
    pub async fn discover(&self) -> Result<KubernetesRuntimeCidrs> {
        let mut cidrs = Vec::new();
        let mut seen = HashSet::new();
        let nodes = self.get_list::<Node>("/api/v1/nodes", "nodes").await?;
        let (node_ips, pod_cidrs) = add_node_runtime_cidrs(&mut cidrs, &mut seen, &nodes.items)?;
        let (service_cidrs, service_cidr_partial) =
            self.discover_service_cidrs(&mut cidrs, &mut seen).await?;

        trace!(
            node_ips,
            pod_cidrs,
            service_cidrs,
            service_cidr_partial,
            total = cidrs.len(),
            "discovered Kubernetes runtime trusted CIDRs"
        );
        Ok(KubernetesRuntimeCidrs {
            cidrs,
            node_ips,
            pod_cidrs,
            service_cidrs,
            service_cidr_partial,
        })
    }

    async fn discover_service_cidrs(
        &self,
        cidrs: &mut Vec<IpNet>,
        seen: &mut HashSet<IpNet>,
    ) -> Result<(usize, bool)> {
        match self
            .get_list_optional::<ServiceCIDR>(
                "/apis/networking.k8s.io/v1/servicecidrs",
                "servicecidrs",
            )
            .await
        {
            Ok(Some(servicecidrs)) => {
                Ok((add_service_cidrs(cidrs, seen, &servicecidrs.items)?, false))
            }
            Ok(None) => self.discover_service_cluster_ips(cidrs, seen).await,
            Err(err) if is_forbidden_error(&err) => {
                warn!(
                    error = %err,
                    "Kubernetes ServiceCIDR API is forbidden; falling back to existing Service ClusterIPs"
                );
                self.discover_service_cluster_ips(cidrs, seen).await
            }
            Err(err) => Err(err),
        }
    }

    async fn discover_service_cluster_ips(
        &self,
        cidrs: &mut Vec<IpNet>,
        seen: &mut HashSet<IpNet>,
    ) -> Result<(usize, bool)> {
        let services = self
            .get_list::<Service>("/api/v1/services", "services")
            .await?;
        Ok((add_service_cluster_ips(cidrs, seen, &services.items)?, true))
    }
}
