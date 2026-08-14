use anyhow::{Context, Result};
use ipnet::IpNet;
use k8s_openapi::api::{core::v1::Service, networking::v1::ServiceCIDR};
use std::collections::HashSet;

use super::{insert_unique, ip_to_host_cidr};

pub(in crate::control_plane::k8s) fn add_service_cidrs(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    servicecidrs: &[ServiceCIDR],
) -> Result<usize> {
    let mut count = 0;
    for servicecidr in servicecidrs {
        if let Some(spec) = &servicecidr.spec
            && let Some(values) = &spec.cidrs
        {
            for value in values {
                let cidr = value
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid Kubernetes ServiceCIDR '{value}'"))?;
                if insert_unique(cidrs, seen, cidr) {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

pub(in crate::control_plane::k8s) fn add_service_cluster_ips(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    services: &[Service],
) -> Result<usize> {
    let mut count = 0;
    for service in services {
        if let Some(spec) = &service.spec {
            count += add_cluster_ips(cidrs, seen, spec.cluster_ips.as_deref())?;
            count += add_cluster_ip(cidrs, seen, spec.cluster_ip.as_deref())?;
        }
    }
    Ok(count)
}

fn add_cluster_ips(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    values: Option<&[String]>,
) -> Result<usize> {
    let mut count = 0;
    for value in values.unwrap_or_default() {
        if add_service_ip(cidrs, seen, value)? {
            count += 1;
        }
    }
    Ok(count)
}

fn add_cluster_ip(
    cidrs: &mut Vec<IpNet>,
    seen: &mut HashSet<IpNet>,
    value: Option<&str>,
) -> Result<usize> {
    Ok(value
        .map(|value| add_service_ip(cidrs, seen, value))
        .transpose()?
        .map_or(0, usize::from))
}

fn add_service_ip(cidrs: &mut Vec<IpNet>, seen: &mut HashSet<IpNet>, value: &str) -> Result<bool> {
    let Some(cidr) = ip_to_host_cidr(value)? else {
        return Ok(false);
    };
    Ok(insert_unique(cidrs, seen, cidr))
}
