use super::{
    GeoPrefix, IpdenyCountryPrefixes, IpdenyMetadata, encode_country, ipdeny_country_url,
    normalize_country,
};
use crate::db::entities::geo_ip_list_state;
use anyhow::{Context, Result};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};

mod parser;

use parser::parse_ipdeny_line;

const IPDENY_COUNTRY_MAX_BYTES: usize = 16 * 1024 * 1024;

pub async fn fetch_ipdeny_metadata(country: &str) -> Result<IpdenyMetadata> {
    fetch_country_metadata(&super::http::ipdeny_client()?, country).await
}

pub async fn fetch_ipdeny_country_prefixes(country: &str) -> Result<IpdenyCountryPrefixes> {
    let client = super::http::ipdeny_client()?;
    let (metadata, prefixes) = fetch_country_prefixes_streaming(&client, country, None)
        .await?
        .context("geo provider returned not-modified without cached metadata")?;
    Ok(IpdenyCountryPrefixes { metadata, prefixes })
}

pub async fn fetch_ipdeny_prefixes(countries: &[String]) -> Result<Vec<GeoPrefix>> {
    let mut prefixes = Vec::new();
    for country in countries {
        prefixes.extend(fetch_ipdeny_country_prefixes(country).await?.prefixes);
    }
    Ok(prefixes)
}

pub(super) async fn fetch_country_metadata(
    client: &reqwest::Client,
    country: &str,
) -> Result<IpdenyMetadata> {
    let country = normalize_country(country)?;
    let url = ipdeny_country_url(&country)?;
    let response = client
        .head(&url)
        .send()
        .await
        .with_context(|| format!("failed to fetch metadata for {url}"))?
        .error_for_status()
        .with_context(|| format!("geo provider returned metadata error for {url}"))?;
    Ok(metadata_from_headers(country, url, response.headers()))
}

pub(super) async fn fetch_country_prefixes_streaming(
    client: &reqwest::Client,
    country: &str,
    existing: Option<&geo_ip_list_state::Model>,
) -> Result<Option<(IpdenyMetadata, Vec<GeoPrefix>)>> {
    let country = normalize_country(country)?;
    let url = ipdeny_country_url(&country)?;
    let response = conditional_country_request(client, &url, existing)
        .send()
        .await
        .with_context(|| format!("failed to fetch {url}"))?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let response = response
        .error_for_status()
        .with_context(|| format!("geo provider returned error for {url}"))?;
    let metadata = metadata_from_headers(country.clone(), url, response.headers());
    let prefixes = read_country_prefixes(response, &country).await?;
    Ok(Some((metadata, prefixes)))
}

fn conditional_country_request(
    client: &reqwest::Client,
    url: &str,
    existing: Option<&geo_ip_list_state::Model>,
) -> reqwest::RequestBuilder {
    let mut request = client.get(url);
    if let Some(existing) = existing {
        request = add_conditional_headers(request, existing);
    }
    request
}

fn add_conditional_headers(
    mut request: reqwest::RequestBuilder,
    existing: &geo_ip_list_state::Model,
) -> reqwest::RequestBuilder {
    if let Some(etag) = existing.etag.as_deref().filter(|value| !value.is_empty()) {
        request = request.header(IF_NONE_MATCH, etag);
    }
    if let Some(last_modified) = existing
        .last_modified
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        request = request.header(IF_MODIFIED_SINCE, last_modified);
    }
    request
}

async fn read_country_prefixes(
    response: reqwest::Response,
    country: &str,
) -> Result<Vec<GeoPrefix>> {
    let country_code = encode_country(country)?;
    super::http::response_lines_limited(response, IPDENY_COUNTRY_MAX_BYTES, |line| {
        Ok(parse_ipdeny_line(country, country_code, line))
    })
    .await
}

fn metadata_from_headers(
    country: String,
    url: String,
    headers: &reqwest::header::HeaderMap,
) -> IpdenyMetadata {
    IpdenyMetadata {
        country,
        url,
        last_modified: super::http::header_string(headers, LAST_MODIFIED),
        etag: super::http::header_string(headers, ETAG),
    }
}
