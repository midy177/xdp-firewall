use super::{GeoPrefix, encode_country, normalize_country};
use crate::db::entities::geo_ip_prefix;
use anyhow::Result;
use ipnet::IpNet;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::net::IpAddr;
use tracing::warn;

mod cidrs;
mod page;

pub use cidrs::geo_prefix_to_cidr;
pub(super) use cidrs::{cidrs_json_from_prefixes, for_each_persisted_cidr, persisted_cidrs};
pub use page::load_persisted_geo_prefix_page;

pub async fn load_persisted_geo_prefixes(
    db: &DatabaseConnection,
    countries: &[String],
) -> Result<Vec<GeoPrefix>> {
    let mut prefixes = Vec::new();
    for country in countries {
        let country = normalize_country(country)?;
        let country_code = encode_country(&country)?;
        let Some(row) = load_geo_ip_prefix_row(db, &country).await? else {
            warn_missing_geo_ip_prefixes(&country);
            continue;
        };
        match for_each_persisted_cidr(&row, |net| {
            prefixes.push(geo_prefix_from_net(net, country_code));
            Ok(())
        }) {
            Ok(_) => {}
            Err(err) => warn_malformed_geo_ip_prefixes(&country, &err),
        }
    }
    Ok(prefixes)
}

pub(super) async fn load_geo_ip_prefix_row(
    db: &DatabaseConnection,
    country: &str,
) -> Result<Option<geo_ip_prefix::Model>> {
    Ok(geo_ip_prefix::Entity::find()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .one(db)
        .await?)
}

pub(super) fn geo_prefix_from_net(net: IpNet, country: u16) -> GeoPrefix {
    let (addr, prefix) = match net {
        IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
        IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
    };
    GeoPrefix {
        addr,
        prefix,
        country,
    }
}

pub(super) fn warn_missing_geo_ip_prefixes(country: &str) {
    warn!(
        country,
        "enabled country rule has no persisted IP list yet; run /geo-countries/refresh"
    );
}

pub(super) fn warn_malformed_geo_ip_prefixes(country: &str, err: &anyhow::Error) {
    warn!(
        country,
        error = %err,
        "skipping malformed persisted country IP list"
    );
}
