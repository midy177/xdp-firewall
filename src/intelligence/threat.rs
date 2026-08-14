use crate::db::{entities::threat_source, scalars};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

mod lock;
mod lookup;
mod persisted;
mod refresh;
mod source_fetch;

pub use lookup::ThreatIntelLookup;
pub use persisted::{
    delete_persisted_threat_prefixes_by_name, enabled_threat_source_states_missing,
    load_persisted_threat_prefixes,
};
pub use refresh::{fetch_threat_prefixes, refresh_enabled_threat_sources};
pub use source_fetch::validate_source_url;

#[cfg(test)]
mod tests;

const MAX_THREAT_BODY_BYTES: usize = 16 * 1024 * 1024;
const THREAT_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const THREAT_HTTP_MAX_REDIRECTS: usize = 3;
const THREAT_LOOKUP_VERSION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinThreatSource {
    pub name: &'static str,
    pub url: &'static str,
    pub format: &'static str,
    pub min_score: Option<i32>,
}

pub const BUILTIN_THREAT_SOURCES: &[BuiltinThreatSource] = &[
    BuiltinThreatSource {
        name: "ipsum",
        url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        format: "ipsum",
        min_score: Some(3),
    },
    BuiltinThreatSource {
        name: "spamhaus-drop",
        url: "https://www.spamhaus.org/drop/drop.txt",
        format: "spamhaus_drop",
        min_score: Some(3),
    },
    BuiltinThreatSource {
        name: "voipbl",
        url: "https://voipbl.org/update/",
        format: "voipbl",
        min_score: Some(3),
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatFormat {
    Cidr,
    Ips,
    Ipsum,
    Voipbl,
    #[serde(rename = "spamhaus_drop")]
    SpamhausDrop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatSource {
    pub name: String,
    pub url: String,
    pub format: ThreatFormat,
    pub min_score: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreatPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRefreshReport {
    pub enabled_source_count: u64,
    pub changed_source_count: u64,
    pub prefix_count: usize,
    pub refreshed: bool,
    pub refresh_status: String,
    #[serde(default)]
    pub cached: bool,
    #[serde(default)]
    pub running: bool,
}

impl TryFrom<threat_source::Model> for ThreatSource {
    type Error = anyhow::Error;

    fn try_from(value: threat_source::Model) -> Result<Self> {
        Ok(Self {
            name: value.name,
            url: value.url,
            format: parse_format(&value.format)?,
            min_score: scalars::optional_i32_to_u32("threat min_score", value.min_score)?,
        })
    }
}

impl ThreatFormat {
    fn label(&self) -> &'static str {
        match self {
            ThreatFormat::Cidr => "cidr",
            ThreatFormat::Ips => "ips",
            ThreatFormat::Ipsum => "ipsum",
            ThreatFormat::Voipbl => "voipbl",
            ThreatFormat::SpamhausDrop => "spamhaus_drop",
        }
    }
}

fn parse_format(value: &str) -> Result<ThreatFormat> {
    match value.to_ascii_lowercase().as_str() {
        "cidr" => Ok(ThreatFormat::Cidr),
        "ips" => Ok(ThreatFormat::Ips),
        "ipsum" => Ok(ThreatFormat::Ipsum),
        "voipbl" | "voipbl_cidr" | "voipbl-cidr" => Ok(ThreatFormat::Voipbl),
        "spamhaus_drop" | "spamhaus-drop" => Ok(ThreatFormat::SpamhausDrop),
        _ => bail!("unsupported threat format '{value}'"),
    }
}
