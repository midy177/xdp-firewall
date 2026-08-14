use anyhow::{Context, Result};
use ipnet::IpNet;
use std::{collections::HashSet, net::IpAddr};

mod nodes;
mod services;

pub(super) use nodes::add_node_runtime_cidrs;
pub(super) use services::{add_service_cidrs, add_service_cluster_ips};

pub(super) fn ip_to_host_cidr(value: &str) -> Result<Option<IpNet>> {
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let ip = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid Kubernetes IP '{value}'"))?;
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Ok(Some(IpNet::new(ip, prefix)?))
}

fn insert_unique(cidrs: &mut Vec<IpNet>, seen: &mut HashSet<IpNet>, cidr: IpNet) -> bool {
    if seen.insert(cidr) {
        cidrs.push(cidr);
        true
    } else {
        false
    }
}
