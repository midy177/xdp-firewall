use anyhow::Result;
use serde_json::Value;
use std::net::IpAddr;
use tracing::warn;

use super::super::ThreatPrefix;
use super::prefix::parse_prefix;

pub(in crate::intelligence::threat) fn parse_lenient_line_prefix(
    line: &str,
    format: &str,
) -> Option<ThreatPrefix> {
    let token = first_prefix_token(line)?;
    match parse_prefix(token) {
        Ok(prefix) => Some(prefix),
        Err(err) => {
            warn!(format, line = line.trim(), error = %err, "skipping invalid threat line");
            None
        }
    }
}

pub(in crate::intelligence::threat) fn parse_ipsum_line(
    line: &str,
    min_score: u32,
) -> Result<Option<ThreatPrefix>> {
    let clean = strip_comment(line);
    let mut parts = clean.split_whitespace();
    let Some(ip) = parts.next() else {
        return Ok(None);
    };
    let score = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1);
    if score >= min_score {
        return Ok(Some(parse_prefix(ip)?));
    }
    Ok(None)
}

pub(in crate::intelligence::threat) fn parse_lenient_ipsum_line(
    line: &str,
    min_score: u32,
) -> Option<ThreatPrefix> {
    match parse_ipsum_line(line, min_score) {
        Ok(prefix) => prefix,
        Err(err) => {
            warn!(format = "ipsum", line = line.trim(), error = %err, "skipping invalid threat line");
            None
        }
    }
}

pub(in crate::intelligence::threat) fn parse_spamhaus_drop(
    body: &str,
) -> Result<Vec<ThreatPrefix>> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        let mut prefixes = Vec::new();
        collect_json_cidrs(&value, &mut prefixes)?;
        if !prefixes.is_empty() {
            return Ok(prefixes);
        }
    }
    let mut prefixes = Vec::new();
    for line in body.lines() {
        if let Some(prefix) = parse_lenient_line_prefix(line, "spamhaus_drop") {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

fn collect_json_cidrs(value: &Value, prefixes: &mut Vec<ThreatPrefix>) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_json_cidrs(value, prefixes)?;
            }
        }
        Value::Object(map) => {
            if let Some(Value::String(cidr)) = map.get("cidr").or_else(|| map.get("prefix")) {
                match parse_prefix(cidr) {
                    Ok(prefix) => prefixes.push(prefix),
                    Err(err) => {
                        warn!(format = "spamhaus_drop", cidr, error = %err, "skipping invalid threat CIDR");
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn first_prefix_token(line: &str) -> Option<&str> {
    strip_comment(line)
        .split_whitespace()
        .find(|token| token.parse::<IpAddr>().is_ok() || token.contains('/'))
}

fn strip_comment(line: &str) -> &str {
    line.split(['#', ';']).next().unwrap_or("").trim()
}
