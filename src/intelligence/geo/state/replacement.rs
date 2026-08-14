use super::{GeoPrefix, IpdenyMetadata, geo_country_catalog, geo_ip_list_state};
use crate::intelligence::geo::persisted::cidrs_json_from_prefixes;
use anyhow::{Context, Result};
use sea_orm::{DatabaseConnection, TransactionTrait};

mod logging;
mod persistence;

use logging::log_geo_prefix_replacement;
use persistence::persist_geo_prefix_replacement;

pub(super) struct GeoPrefixReplacement {
    country: String,
    url: String,
    last_modified: Option<String>,
    etag: Option<String>,
    prefix_count: i32,
    cidrs_json: String,
    cidrs_json_bytes: usize,
    existing_state_updated_at: Option<chrono::NaiveDateTime>,
    now: chrono::NaiveDateTime,
}

pub(in crate::intelligence::geo) async fn replace_geo_prefixes(
    db: &DatabaseConnection,
    catalog: &geo_country_catalog::Model,
    existing_state: Option<&geo_ip_list_state::Model>,
    metadata: &IpdenyMetadata,
    prefixes: &[GeoPrefix],
) -> Result<bool> {
    let replacement = GeoPrefixReplacement::new(catalog, existing_state, metadata, prefixes)?;
    let log_country = replacement.country.clone();
    let prefix_count = replacement.prefix_count;
    let cidrs_json_bytes = replacement.cidrs_json_bytes;
    let changed = db
        .transaction::<_, bool, sea_orm::DbErr>(|txn| {
            Box::pin(async move { persist_geo_prefix_replacement(txn, replacement).await })
        })
        .await?;
    if changed {
        log_geo_prefix_replacement(&log_country, prefix_count, cidrs_json_bytes);
    }
    Ok(changed)
}

impl GeoPrefixReplacement {
    fn new(
        catalog: &geo_country_catalog::Model,
        existing_state: Option<&geo_ip_list_state::Model>,
        metadata: &IpdenyMetadata,
        prefixes: &[GeoPrefix],
    ) -> Result<Self> {
        let cidrs_json = cidrs_json_from_prefixes(prefixes);
        let now = chrono::Utc::now().naive_utc();
        Ok(Self {
            country: catalog.code.clone(),
            url: metadata.url.clone(),
            last_modified: metadata.last_modified.clone(),
            etag: metadata.etag.clone(),
            prefix_count: i32::try_from(prefixes.len()).context("geo prefix count exceeds i32")?,
            cidrs_json_bytes: cidrs_json.len(),
            cidrs_json,
            existing_state_updated_at: existing_state.map(|state| state.updated_at),
            now,
        })
    }
}
