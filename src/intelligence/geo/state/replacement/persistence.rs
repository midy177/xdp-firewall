use super::{GeoPrefixReplacement, geo_ip_list_state};
use crate::intelligence::geo::state::geo_ip_prefix;
use crate::{db, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, sea_query::OnConflict,
};

pub(super) async fn persist_geo_prefix_replacement(
    txn: &sea_orm::DatabaseTransaction,
    replacement: GeoPrefixReplacement,
) -> std::result::Result<bool, sea_orm::DbErr> {
    let GeoPrefixReplacement {
        country,
        url,
        last_modified,
        etag,
        prefix_count,
        cidrs_json,
        cidrs_json_bytes: _,
        existing_state_updated_at,
        now,
    } = replacement;
    let prefixes_changed = geo_ip_prefixes_changed(txn, &country, &cidrs_json).await?;
    let updated_at = geo_ip_list_state_updated_at(prefixes_changed, existing_state_updated_at, now);
    if prefixes_changed {
        replace_geo_ip_prefix_row(txn, &country, cidrs_json, now).await?;
    }
    upsert_geo_ip_list_state(
        txn,
        GeoIpListStateReplacement {
            country,
            url,
            last_modified,
            etag,
            prefix_count,
            now,
            updated_at,
        },
    )
    .await?;
    if prefixes_changed {
        db::next_policy_version_in_transaction(txn, DEFAULT_POLICY_NAME).await?;
    }
    Ok(prefixes_changed)
}

fn geo_ip_list_state_updated_at(
    prefixes_changed: bool,
    existing_updated_at: Option<chrono::NaiveDateTime>,
    now: chrono::NaiveDateTime,
) -> chrono::NaiveDateTime {
    if prefixes_changed {
        return now;
    }
    existing_updated_at.unwrap_or(now)
}

struct GeoIpListStateReplacement {
    country: String,
    url: String,
    last_modified: Option<String>,
    etag: Option<String>,
    prefix_count: i32,
    now: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

async fn geo_ip_prefixes_changed(
    txn: &sea_orm::DatabaseTransaction,
    country: &str,
    cidrs_json: &str,
) -> std::result::Result<bool, sea_orm::DbErr> {
    Ok(geo_ip_prefix::Entity::find()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .one(txn)
        .await?
        .is_none_or(|row| row.cidrs_json != cidrs_json))
}

async fn replace_geo_ip_prefix_row(
    txn: &sea_orm::DatabaseTransaction,
    country: &str,
    cidrs_json: String,
    now: chrono::NaiveDateTime,
) -> std::result::Result<(), sea_orm::DbErr> {
    geo_ip_prefix::Entity::delete_many()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .exec(txn)
        .await?;
    geo_ip_prefix::ActiveModel {
        country: Set(country.to_string()),
        cidrs_json: Set(cidrs_json),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(txn)
    .await?;
    Ok(())
}

async fn upsert_geo_ip_list_state(
    txn: &sea_orm::DatabaseTransaction,
    replacement: GeoIpListStateReplacement,
) -> std::result::Result<(), sea_orm::DbErr> {
    geo_ip_list_state::Entity::insert(geo_ip_list_state::ActiveModel {
        country: Set(replacement.country),
        url: Set(replacement.url),
        last_modified: Set(replacement.last_modified),
        etag: Set(replacement.etag),
        prefix_count: Set(replacement.prefix_count),
        last_checked_at: Set(replacement.now),
        last_downloaded_at: Set(Some(replacement.now)),
        updated_at: Set(replacement.updated_at),
        ..Default::default()
    })
    .on_conflict(geo_ip_list_state_upsert_conflict())
    .exec_without_returning(txn)
    .await?;
    Ok(())
}

fn geo_ip_list_state_upsert_conflict() -> OnConflict {
    OnConflict::column(geo_ip_list_state::Column::Country)
        .update_columns([
            geo_ip_list_state::Column::Url,
            geo_ip_list_state::Column::LastModified,
            geo_ip_list_state::Column::Etag,
            geo_ip_list_state::Column::PrefixCount,
            geo_ip_list_state::Column::LastCheckedAt,
            geo_ip_list_state::Column::LastDownloadedAt,
            geo_ip_list_state::Column::UpdatedAt,
        ])
        .to_owned()
}
