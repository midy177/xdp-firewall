use anyhow::{Context, Result};
use ipnet::IpNet;
use k8s_openapi::api::core::v1::Node;
use std::collections::HashSet;

use super::{insert_unique, ip_to_host_cidr};

pub(in crate::control_plane::k8s) fn add_node_runtime_cidrs(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    nodes: &[Node],
) -> Result<(usize, usize)> {
    let mut node_ips = 0;
    let mut pod_cidrs = 0;
    for node in nodes {
        node_ips += add_node_addresses(cidrs, seen, node)?;
        pod_cidrs += add_node_pod_cidrs(cidrs, seen, node)?;
    }
    Ok((node_ips, pod_cidrs))
}

fn add_node_addresses(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    node: &Node,
) -> Result<usize> {
    let mut count = 0;
    let Some(status) = &node.status else {
        return Ok(0);
    };
    let Some(addresses) = &status.addresses else {
        return Ok(0);
    };
    for address in addresses {
        if matches!(address.type_.as_str(), "InternalIP" | "ExternalIP")
            && let Some(cidr) = ip_to_host_cidr(&address.address)?
            && insert_unique(cidrs, seen, cidr)
        {
            count += 1;
        }
    }
    Ok(count)
}

fn add_node_pod_cidrs(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    node: &Node,
) -> Result<usize> {
    let Some(spec) = &node.spec else {
        return Ok(0);
    };
    let mut count = 0;
    let mut node_has_pod_cidr = false;
    for value in spec.pod_cidrs.as_deref().unwrap_or_default() {
        node_has_pod_cidr = true;
        if insert_pod_cidr(cidrs, seen, value)? {
            count += 1;
        }
    }
    if !node_has_pod_cidr
        && let Some(value) = spec.pod_cidr.as_deref()
        && insert_pod_cidr(cidrs, seen, value)?
    {
        count += 1;
    }
    Ok(count)
}

fn insert_pod_cidr(cidrs: &mut Vec<IpNet>, seen: &mut HashSet<IpNet>, value: &str) -> Result<bool> {
    let cidr = value
        .parse::<IpNet>()
        .with_context(|| format!("invalid Kubernetes podCIDR '{value}'"))?;
    Ok(insert_unique(cidrs, seen, cidr))
}
