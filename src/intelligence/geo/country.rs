use anyhow::{Context, Result, bail};

use super::IPDENY_AGGREGATED_BASE;

pub fn ipdeny_country_url(country: &str) -> Result<String> {
    let country = normalize_country(country)?;
    Ok(format!(
        "{IPDENY_AGGREGATED_BASE}/{}-aggregated.zone",
        country.to_ascii_lowercase()
    ))
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

pub fn decode_country(country: u16) -> Result<String> {
    let first = ((country >> 8) & 0xff) as u8;
    let second = (country & 0xff) as u8;
    let code = String::from_utf8(vec![first, second]).context("invalid encoded country")?;
    normalize_country(&code)
}
