use super::super::ThreatPrefix;
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::{collections::HashSet, net::IpAddr};

pub(in crate::intelligence::threat) fn parse_prefix(value: &str) -> Result<ThreatPrefix> {
    let value = value.trim().trim_matches(',').trim_matches('"');
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(match net {
            IpNet::V4(net) => ThreatPrefix {
                addr: IpAddr::V4(net.network()),
                prefix: net.prefix_len(),
            },
            IpNet::V6(net) => ThreatPrefix {
                addr: IpAddr::V6(net.network()),
                prefix: net.prefix_len(),
            },
        });
    }
    let addr = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid threat IP/CIDR '{value}'"))?;
    Ok(ThreatPrefix {
        addr,
        prefix: if addr.is_ipv4() { 32 } else { 128 },
    })
}

pub(in crate::intelligence::threat) fn normalize_prefixes(
    prefixes: Vec<ThreatPrefix>,
) -> Vec<ThreatPrefix> {
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();
    for prefix in prefixes {
        if unique.insert(prefix) {
            normalized.push(prefix);
        }
    }
    normalized.sort_by_key(|prefix| (prefix.addr.is_ipv6(), prefix.addr, prefix.prefix));
    normalized
}

pub(in crate::intelligence::threat) fn threat_prefix_fingerprint(
    prefixes: &[ThreatPrefix],
) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for prefix in prefixes {
        hash = hash_bytes(hash, prefix.addr.to_string().as_bytes());
        hash = hash_byte(hash, b'/');
        hash = hash_bytes(hash, prefix.prefix.to_string().as_bytes());
        hash = hash_byte(hash, b'\n');
    }
    format!("{hash:016x}")
}

pub(in crate::intelligence::threat) fn prefix_to_cidr(prefix: &ThreatPrefix) -> String {
    match prefix.addr {
        IpAddr::V4(addr) => format!("{addr}/{}", prefix.prefix),
        IpAddr::V6(addr) => format!("{addr}/{}", prefix.prefix),
    }
}

fn hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = hash_byte(hash, *byte);
    }
    hash
}

fn hash_byte(mut hash: u64, byte: u8) -> u64 {
    hash ^= u64::from(byte);
    hash.wrapping_mul(0x0100_0000_01b3)
}
