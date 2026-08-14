use super::IPDENY_ROOT;
use crate::db::entities::geo_country_catalog;
use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    sea_query::OnConflict,
};
use serde::Serialize;

mod parser;

pub(super) use parser::{IpdenyIndexEntry, parse_ipdeny_index};

const IPDENY_INDEX_MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CountryOption {
    pub code: String,
    pub name: String,
}

pub async fn refresh_ipdeny_country_catalog(db: &DatabaseConnection) -> Result<Vec<CountryOption>> {
    let entries = fetch_ipdeny_index_entries().await?;
    let now = chrono::Utc::now().naive_utc();
    for entry in &entries {
        upsert_country_catalog_entry(db, entry, now).await?;
    }
    list_country_options(db).await
}

pub async fn list_country_options(db: &DatabaseConnection) -> Result<Vec<CountryOption>> {
    Ok(geo_country_catalog::Entity::find()
        .order_by_asc(geo_country_catalog::Column::Code)
        .all(db)
        .await?
        .into_iter()
        .map(|row| CountryOption {
            code: row.code,
            name: row.name,
        })
        .collect())
}

async fn fetch_ipdeny_index_entries() -> Result<Vec<IpdenyIndexEntry>> {
    let client = super::http::ipdeny_client()?;
    let body = super::http::fetch_text_limited(&client, IPDENY_ROOT, IPDENY_INDEX_MAX_BYTES)
        .await
        .with_context(|| format!("failed to fetch {IPDENY_ROOT}"))?;
    parse_ipdeny_index(&body)
}

async fn upsert_country_catalog_entry(
    db: &DatabaseConnection,
    entry: &IpdenyIndexEntry,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    let existing = geo_country_catalog::Entity::find()
        .filter(geo_country_catalog::Column::Code.eq(&entry.country))
        .one(db)
        .await?;
    geo_country_catalog::Entity::insert(geo_country_catalog::ActiveModel {
        code: Set(entry.country.clone()),
        name: Set(entry.name.clone()),
        url: Set(entry.url.clone()),
        last_modified: Set(entry.last_modified.clone()),
        size_bytes: Set(entry.size_bytes),
        last_checked_at: Set(now),
        updated_at: Set(country_catalog_updated_at(existing.as_ref(), entry, now)),
        ..Default::default()
    })
    .on_conflict(country_catalog_upsert_conflict())
    .exec_without_returning(db)
    .await?;
    Ok(())
}

pub(super) fn country_catalog_updated_at(
    existing: Option<&geo_country_catalog::Model>,
    entry: &IpdenyIndexEntry,
    now: chrono::NaiveDateTime,
) -> chrono::NaiveDateTime {
    let Some(existing) = existing else {
        return now;
    };
    if country_catalog_entry_changed(existing, entry) {
        now
    } else {
        existing.updated_at
    }
}

fn country_catalog_entry_changed(
    existing: &geo_country_catalog::Model,
    entry: &IpdenyIndexEntry,
) -> bool {
    existing.name != entry.name
        || existing.url != entry.url
        || existing.last_modified != entry.last_modified
        || existing.size_bytes != entry.size_bytes
}

fn country_catalog_upsert_conflict() -> OnConflict {
    OnConflict::column(geo_country_catalog::Column::Code)
        .update_columns([
            geo_country_catalog::Column::Name,
            geo_country_catalog::Column::Url,
            geo_country_catalog::Column::LastModified,
            geo_country_catalog::Column::SizeBytes,
            geo_country_catalog::Column::LastCheckedAt,
            geo_country_catalog::Column::UpdatedAt,
        ])
        .to_owned()
}
