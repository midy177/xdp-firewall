use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::HashSet;

pub(in crate::control_plane::xds) struct CidrCompaction {
    pub(in crate::control_plane::xds) cidrs: Vec<IpNet>,
    pub(in crate::control_plane::xds) covered: usize,
}

pub(in crate::control_plane::xds) fn compact_covered_cidrs(cidrs: &[IpNet]) -> CidrCompaction {
    let mut compacted = Vec::with_capacity(cidrs.len());
    for (index, cidr) in cidrs.iter().enumerate() {
        if cidrs
            .iter()
            .enumerate()
            .any(|(other_index, other)| other_index != index && cidr_covers(*other, *cidr))
        {
            continue;
        }
        compacted.push(*cidr);
    }
    let covered = cidrs.len().saturating_sub(compacted.len());
    CidrCompaction {
        cidrs: compacted,
        covered,
    }
}

pub(in crate::control_plane::xds) fn cidr_fingerprint(cidrs: &[IpNet]) -> String {
    let mut values = cidrs.iter().map(ToString::to_string).collect::<Vec<_>>();
    values.sort();
    values.join(",")
}

pub(in crate::control_plane::xds) fn normalize_runtime_trusted_cidrs(
    values: &[String],
) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();
    let mut seen = HashSet::new();
    for value in values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let cidr = value
            .parse::<IpNet>()
            .with_context(|| format!("invalid runtime trusted CIDR '{value}'"))?;
        if seen.insert(cidr) {
            cidrs.push(cidr);
        }
    }
    Ok(cidrs)
}

fn cidr_covers(cover: IpNet, cidr: IpNet) -> bool {
    if cover == cidr || cover.prefix_len() > cidr.prefix_len() {
        return false;
    }
    match (cover, cidr) {
        (IpNet::V4(cover), IpNet::V4(cidr)) => cover.contains(&cidr.network()),
        (IpNet::V6(cover), IpNet::V6(cidr)) => cover.contains(&cidr.network()),
        _ => false,
    }
}
