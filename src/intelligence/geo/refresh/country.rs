use crate::db::entities::{geo_country_catalog, geo_ip_list_state};
use anyhow::{Result, bail};
use sea_orm::DatabaseConnection;
use tracing::{debug, info, warn};

use super::super::{
    IpdenyMetadata, fetch_country_metadata, fetch_country_prefixes_streaming,
    state::{
        has_persisted_country_prefixes, load_geo_country_catalog_row, load_geo_ip_list_state,
        replace_geo_prefixes, touch_existing_geo_ip_state,
    },
};

pub(super) async fn refresh_one_country(
    db: &DatabaseConnection,
    client: &reqwest::Client,
    country: &str,
) -> Result<Option<usize>> {
    let catalog = load_geo_country_catalog_row(db, country).await?;
    let existing = load_geo_ip_list_state(db, country).await?;
    let has_persisted_prefixes = has_persisted_country_prefixes(db, country).await?;
    let metadata =
        fetch_country_metadata_or_catalog(client, country, &catalog, existing.as_ref()).await;

    if !geo_ip_list_changed(
        existing.as_ref(),
        has_persisted_prefixes,
        metadata.last_modified.as_deref(),
        metadata.etag.as_deref(),
    ) {
        touch_existing_geo_ip_state(db, existing, &metadata).await?;
        debug!(country, "country IP list unchanged");
        return Ok(None);
    }

    let fetched = fetch_country_prefixes_streaming(client, country, existing.as_ref()).await?;
    let Some((fetched_metadata, prefixes)) = fetched else {
        touch_existing_geo_ip_state(db, existing, &metadata).await?;
        debug!(country, "country IP list returned not-modified");
        return Ok(None);
    };
    if prefixes.is_empty() {
        bail!("country {country} IP list is empty");
    }
    let count = prefixes.len();
    let metadata = merge_geo_ip_metadata(fetched_metadata, metadata);
    if !replace_geo_prefixes(db, &catalog, existing.as_ref(), &metadata, &prefixes).await? {
        debug!(country, "country IP list payload unchanged");
        return Ok(None);
    }
    info!(country, prefixes = count, "country IP list refreshed");
    Ok(Some(count))
}

async fn fetch_country_metadata_or_catalog(
    client: &reqwest::Client,
    country: &str,
    catalog: &geo_country_catalog::Model,
    existing: Option<&geo_ip_list_state::Model>,
) -> IpdenyMetadata {
    fetch_country_metadata(client, country)
        .await
        .unwrap_or_else(|err| {
            warn!(
                country,
                error = %err,
                "failed to fetch country IP metadata; falling back to catalog metadata"
            );
            IpdenyMetadata {
                country: country.to_string(),
                url: catalog.url.clone(),
                last_modified: catalog.last_modified.clone(),
                etag: existing.and_then(|row| row.etag.clone()),
            }
        })
}

fn merge_geo_ip_metadata(fetched: IpdenyMetadata, fallback: IpdenyMetadata) -> IpdenyMetadata {
    IpdenyMetadata {
        country: fetched.country,
        url: fetched.url,
        last_modified: fetched.last_modified.or(fallback.last_modified),
        etag: fetched.etag.or(fallback.etag),
    }
}

pub(in crate::intelligence::geo) fn geo_ip_list_changed(
    existing: Option<&geo_ip_list_state::Model>,
    has_persisted_prefixes: bool,
    last_modified: Option<&str>,
    etag: Option<&str>,
) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    if !has_persisted_prefixes {
        return true;
    }
    if last_modified.is_none() && etag.is_none() {
        return true;
    }
    existing.last_modified.as_deref() != last_modified || existing.etag.as_deref() != etag
}
