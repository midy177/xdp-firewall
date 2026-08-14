use anyhow::Result;
use sea_orm::DatabaseConnection;
use std::collections::BTreeSet;
use tracing::warn;

use super::{
    GeoRefreshReport, IPDENY_ROOT, ipdeny_client, lock::GeoRefreshDbLock, normalize_country,
    refresh_ipdeny_country_catalog,
};

mod country;

#[cfg(test)]
pub(super) use country::geo_ip_list_changed;
use country::refresh_one_country;

pub async fn refresh_ipdeny_lists(
    db: &DatabaseConnection,
    countries: &[String],
) -> Result<GeoRefreshReport> {
    let Some(_guard) = GeoRefreshDbLock::try_acquire(db).await? else {
        return Ok(GeoRefreshReport::running());
    };
    refresh_ipdeny_country_catalog(db).await?;
    let mut requested = BTreeSet::new();
    for country in countries {
        requested.insert(normalize_country(country)?);
    }
    refresh_ipdeny_lists_for_countries(db, requested.into_iter().collect()).await
}

pub async fn refresh_all_ipdeny_lists(db: &DatabaseConnection) -> Result<GeoRefreshReport> {
    let Some(_guard) = GeoRefreshDbLock::try_acquire(db).await? else {
        return Ok(GeoRefreshReport::running());
    };
    let countries = refresh_ipdeny_country_catalog(db)
        .await?
        .into_iter()
        .map(|country| country.code)
        .collect::<Vec<_>>();
    refresh_ipdeny_lists_for_countries(db, countries).await
}

async fn refresh_ipdeny_lists_for_countries(
    db: &DatabaseConnection,
    countries: Vec<String>,
) -> Result<GeoRefreshReport> {
    let mut changed_country_count = 0_usize;
    let mut unchanged_country_count = 0_usize;
    let mut failed_country_count = 0_usize;
    let mut prefix_count = 0_usize;
    let mut errors = Vec::new();
    let client = ipdeny_client()?;
    for country in &countries {
        match refresh_one_country(db, &client, country).await {
            Ok(Some(count)) => {
                changed_country_count += 1;
                prefix_count += count;
            }
            Ok(None) => {
                unchanged_country_count += 1;
            }
            Err(err) => {
                failed_country_count += 1;
                errors.push(format!("{country}: {err:#}"));
                warn!(
                    country,
                    error = %err,
                    "skipping country IP refresh after provider or parsing error"
                );
            }
        }
    }
    Ok(GeoRefreshReport {
        checked_country_count: countries.len(),
        changed_country_count,
        unchanged_country_count,
        failed_country_count,
        countries,
        prefix_count,
        provider_base_url: IPDENY_ROOT,
        refresh_status: if failed_country_count == 0 {
            "completed".to_string()
        } else if changed_country_count > 0 || unchanged_country_count > 0 {
            "partial_failed".to_string()
        } else {
            "failed".to_string()
        },
        cached: false,
        running: false,
        errors,
    })
}
