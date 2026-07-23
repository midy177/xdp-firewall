use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;

const IPDENY_BASE: &str = "https://www.ipdeny.com/ipblocks/data/aggregated";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
    pub country: u16,
}

pub async fn fetch_ipdeny_prefixes(countries: &[String]) -> Result<Vec<GeoPrefix>> {
    let mut prefixes = Vec::new();
    for country in countries {
        let country = normalize_country(country)?;
        let url = format!(
            "{IPDENY_BASE}/{}-aggregated.zone",
            country.to_ascii_lowercase()
        );
        let body = reqwest::get(&url)
            .await
            .with_context(|| format!("failed to fetch {url}"))?
            .error_for_status()
            .with_context(|| format!("geo provider returned error for {url}"))?
            .text()
            .await?;
        let country_code = encode_country(&country)?;
        for line in body.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let net = line
                .parse::<IpNet>()
                .with_context(|| format!("invalid geo CIDR '{line}' for {country}"))?;
            let (addr, prefix) = match net {
                IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
                IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
            };
            prefixes.push(GeoPrefix {
                addr,
                prefix,
                country: country_code,
            });
        }
    }
    Ok(prefixes)
}

pub fn normalize_country(value: &str) -> Result<String> {
    let value = value.trim();
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        bail!("invalid ISO country code '{value}'");
    }
    Ok(value.to_ascii_uppercase())
}

pub fn encode_country(value: &str) -> Result<u16> {
    let value = normalize_country(value)?;
    let bytes = value.as_bytes();
    Ok(u16::from(bytes[0]) << 8 | u16::from(bytes[1]))
}
