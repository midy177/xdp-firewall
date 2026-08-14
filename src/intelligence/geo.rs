use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};

mod catalog;
mod country;
mod http;
mod lock;
mod lookup;
mod memory;
mod persisted;
mod provider;
mod refresh;
mod report;
mod state;

#[cfg(test)]
mod tests;

pub use catalog::{CountryOption, list_country_options, refresh_ipdeny_country_catalog};
pub use country::{decode_country, encode_country, ipdeny_country_url, normalize_country};
use http::ipdeny_client;
pub use lookup::GeoIpLookup;
pub use persisted::{
    geo_prefix_to_cidr, load_persisted_geo_prefix_page, load_persisted_geo_prefixes,
};
use provider::{fetch_country_metadata, fetch_country_prefixes_streaming};
pub use provider::{fetch_ipdeny_country_prefixes, fetch_ipdeny_metadata, fetch_ipdeny_prefixes};
pub use refresh::{refresh_all_ipdeny_lists, refresh_ipdeny_lists};
pub use report::GeoRefreshReport;

#[cfg(test)]
use crate::db::entities::geo_country_catalog;
#[cfg(test)]
use refresh::geo_ip_list_changed;

const IPDENY_ROOT: &str = "https://www.ipdeny.com/ipblocks/";
const IPDENY_AGGREGATED_BASE: &str = "https://www.ipdeny.com/ipblocks/data/aggregated";
const IPDENY_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const GEOIP_REBUILD_PAGE_SIZE: u64 = 16;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
    pub country: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoPrefixPage {
    pub prefixes: Vec<GeoPrefix>,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpdenyMetadata {
    pub country: String,
    pub url: String,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IpdenyCountryPrefixes {
    pub metadata: IpdenyMetadata,
    pub prefixes: Vec<GeoPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdbCountryRecord {
    pub country: MmdbCountry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdbCountry {
    pub iso_code: String,
    pub names: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeoIpCountry {
    pub code: String,
    pub name: Option<String>,
}

#[must_use]
pub fn ipdeny_base_url() -> &'static str {
    IPDENY_AGGREGATED_BASE
}
