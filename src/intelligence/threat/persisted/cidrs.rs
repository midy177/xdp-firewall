use crate::{
    db::entities::threat_prefix,
    intelligence::threat::{
        ThreatPrefix,
        source_fetch::{parse_prefix, prefix_to_cidr},
    },
};
use anyhow::{Context, Result};

pub(in crate::intelligence::threat) fn persisted_prefixes(
    row: &threat_prefix::Model,
) -> Result<Vec<ThreatPrefix>> {
    let cidrs = serde_json::from_str::<Vec<String>>(&row.cidrs_json)
        .with_context(|| format!("invalid persisted threat CIDR list for {}", row.source_name))?;
    cidrs
        .iter()
        .map(|cidr| parse_prefix(cidr))
        .collect::<Result<Vec<_>>>()
}

pub(in crate::intelligence::threat) fn cidrs_json_from_prefixes(
    prefixes: &[ThreatPrefix],
) -> String {
    let cidrs = prefixes.iter().map(prefix_to_cidr).collect::<Vec<_>>();
    serde_json::to_string(&cidrs).expect("threat CIDR list should serialize")
}
