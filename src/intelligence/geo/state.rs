use super::{GeoPrefix, IpdenyMetadata};
use crate::db::entities::{geo_country_catalog, geo_ip_list_state, geo_ip_prefix};
use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use super::persisted::persisted_cidrs;

mod replacement;

pub(super) use replacement::replace_geo_prefixes;

pub(super) async fn load_geo_country_catalog_row(
    db: &DatabaseConnection,
    country: &str,
) -> Result<geo_country_catalog::Model> {
    geo_country_catalog::Entity::find()
        .filter(geo_country_catalog::Column::Code.eq(country))
        .one(db)
        .await?
        .with_context(|| format!("country {country} not found in IPdeny catalog"))
}

pub(super) async fn load_geo_ip_list_state(
    db: &DatabaseConnection,
    country: &str,
) -> Result<Option<geo_ip_list_state::Model>> {
    Ok(geo_ip_list_state::Entity::find()
        .filter(geo_ip_list_state::Column::Country.eq(country))
        .one(db)
        .await?)
}

pub(super) async fn has_persisted_country_prefixes(
    db: &DatabaseConnection,
    country: &str,
) -> Result<bool> {
    Ok(geo_ip_prefix::Entity::find()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .one(db)
        .await?
        .as_ref()
        .is_some_and(|row| persisted_cidrs(row).is_ok_and(|cidrs| !cidrs.is_empty())))
}

pub(super) async fn touch_existing_geo_ip_state(
    db: &DatabaseConnection,
    existing: Option<geo_ip_list_state::Model>,
    metadata: &IpdenyMetadata,
) -> Result<()> {
    if let Some(existing) = existing {
        touch_geo_ip_list_state(
            db,
            existing,
            metadata.last_modified.clone(),
            metadata.etag.clone(),
        )
        .await?;
    }
    Ok(())
}

async fn touch_geo_ip_list_state(
    db: &DatabaseConnection,
    existing: geo_ip_list_state::Model,
    last_modified: Option<String>,
    etag: Option<String>,
) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let mut active: geo_ip_list_state::ActiveModel = existing.into();
    active.last_modified = Set(last_modified);
    active.etag = Set(etag);
    active.last_checked_at = Set(now);
    active.update(db).await?;
    Ok(())
}
