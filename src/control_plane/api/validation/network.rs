use super::super::{ApiError, ApiResult};
use crate::{db::entities::node, policy::model::DEFAULT_POLICY_NAME};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::net::IpAddr;
use tracing::warn;

pub(in crate::control_plane::api) fn normalize_cidr(value: &str) -> Result<String> {
    let cidr = value.trim();
    if !cidr.contains('/') {
        bail!("CIDR must include a prefix length");
    }
    let net = cidr
        .parse::<IpNet>()
        .with_context(|| format!("invalid CIDR '{cidr}'"))?;
    Ok(match net {
        IpNet::V4(net) => format!("{}/{}", net.network(), net.prefix_len()),
        IpNet::V6(net) => format!("{}/{}", net.network(), net.prefix_len()),
    })
}

pub(in crate::control_plane::api) fn parse_normalized_cidr(value: &str) -> Result<IpNet> {
    normalize_cidr(value)?
        .parse::<IpNet>()
        .with_context(|| format!("invalid normalized CIDR '{value}'"))
}

pub(in crate::control_plane::api) async fn reject_node_ip_block(
    db: &DatabaseConnection,
    cidr: IpNet,
    resource: &str,
) -> ApiResult<()> {
    let rows = node::Entity::find()
        .filter(node::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .all(db)
        .await?;
    for row in rows {
        for ip in parse_node_interface_ips(&row.interface_ips)? {
            if cidr_contains_ip(cidr, ip) {
                warn!(
                    resource,
                    cidr = %cidr,
                    node_id = %row.node_id,
                    interface = %row.interface_name,
                    ip = %ip,
                    "rejected configuration because it would block a node interface IP"
                );
                return Err(ApiError::bad_request(format!(
                    "{resource} CIDR {cidr} contains node {} interface {} IP {ip}",
                    row.node_id, row.interface_name
                )));
            }
        }
    }
    Ok(())
}

pub(in crate::control_plane::api) fn parse_node_interface_ips(value: &str) -> Result<Vec<IpAddr>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpAddr>()
                .with_context(|| format!("invalid persisted node interface IP '{value}'"))
        })
        .collect()
}

fn cidr_contains_ip(cidr: IpNet, ip: IpAddr) -> bool {
    match (cidr, ip) {
        (IpNet::V4(cidr), IpAddr::V4(ip)) => cidr.contains(&ip),
        (IpNet::V6(cidr), IpAddr::V6(ip)) => cidr.contains(&ip),
        _ => false,
    }
}
