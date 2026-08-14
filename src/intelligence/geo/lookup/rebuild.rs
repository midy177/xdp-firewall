use crate::db::entities::{geo_country_catalog, geo_ip_prefix};
use anyhow::Result;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait, QueryOrder};
use std::collections::HashMap;
use tracing::warn;

mod writer;

use super::GeoIpRebuildFile;
use crate::intelligence::geo::GEOIP_REBUILD_PAGE_SIZE;
use writer::GeoIpMmdbBuilder;

pub(super) async fn build_geoip_rebuild_file(
    db: &DatabaseConnection,
    country_names: &HashMap<String, String>,
) -> Result<(Option<GeoIpRebuildFile>, usize)> {
    let mut builder = GeoIpMmdbBuilder::new();
    let paginator = geo_ip_prefix::Entity::find()
        .order_by_asc(geo_ip_prefix::Column::Country)
        .paginate(db, GEOIP_REBUILD_PAGE_SIZE);
    let pages = paginator.num_pages().await?;
    for page in 0..pages {
        builder.write_page(country_names, paginator.fetch_page(page).await?)?;
    }

    let skipped_ipv6 = builder.skipped_ipv6();
    Ok((builder.into_rebuild_file()?, skipped_ipv6))
}

pub(super) async fn load_geo_country_names(
    db: &DatabaseConnection,
) -> Result<HashMap<String, String>> {
    Ok(geo_country_catalog::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|row| (row.code, row.name))
        .collect())
}

pub(super) fn log_skipped_ipv6_prefixes(skipped_ipv6: usize) {
    if skipped_ipv6 > 0 {
        warn!(
            skipped_ipv6,
            "skipped IPv6 country prefixes while rebuilding IPv4 IPdeny MMDB"
        );
    }
}
