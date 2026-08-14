use crate::policy::model::{PolicySnapshot, TrustedCidrPolicy};
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::net::IpAddr;
use tracing::warn;

pub(super) fn add_control_plane_trusted_cidrs(
    snapshot: &mut PolicySnapshot,
    control_url: &str,
) -> Result<()> {
    let prefixes = resolve_control_plane_prefixes(control_url)?;
    for cidr in prefixes {
        add_control_plane_trusted_cidr(snapshot, cidr);
    }
    Ok(())
}

fn add_control_plane_trusted_cidr(snapshot: &mut PolicySnapshot, cidr: IpNet) {
    if snapshot
        .trusted_cidrs
        .iter()
        .any(|trusted| trusted.cidr == cidr)
    {
        return;
    }
    snapshot.trusted_cidrs.push(TrustedCidrPolicy {
        cidr,
        comment: Some("local xDS control-plane allow".to_string()),
    });
}

fn resolve_control_plane_prefixes(control_url: &str) -> Result<Vec<IpNet>> {
    let (host, _) = control_plane_host_port(control_url)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip_literal_prefix(ip)?]);
    }
    warn!(
        host,
        "xDS control URL host is not an IP literal; skipping automatic local control-plane allow to avoid DNS-based bypass"
    );
    Ok(Vec::new())
}

fn ip_literal_prefix(ip: IpAddr) -> Result<IpNet> {
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    IpNet::new(ip, prefix)
        .with_context(|| format!("failed to build xDS control-plane CIDR for {ip}"))
}

fn control_plane_host_port(control_url: &str) -> Result<(String, u16)> {
    let without_scheme = control_url
        .strip_prefix("http://")
        .or_else(|| control_url.strip_prefix("https://"))
        .unwrap_or(control_url);
    let authority = without_scheme
        .split('/')
        .next()
        .filter(|value| !value.is_empty())
        .context("xDS control URL is missing a host")?;
    if let Some(host) = authority.strip_prefix('[') {
        return bracketed_host_port(host);
    }
    unbracketed_host_port(authority)
}

fn bracketed_host_port(authority: &str) -> Result<(String, u16)> {
    let (host, rest) = authority
        .split_once(']')
        .context("invalid bracketed IPv6 xDS control URL host")?;
    let port = rest
        .strip_prefix(':')
        .map(str::parse)
        .transpose()?
        .unwrap_or(50051);
    Ok((host.to_string(), port))
}

fn unbracketed_host_port(authority: &str) -> Result<(String, u16)> {
    Ok(authority
        .rsplit_once(':')
        .map(|(host, port)| {
            let port = port
                .parse::<u16>()
                .context("invalid xDS control URL port")?;
            Ok::<_, anyhow::Error>((host.to_string(), port))
        })
        .transpose()?
        .unwrap_or_else(|| (authority.to_string(), 50051)))
}
