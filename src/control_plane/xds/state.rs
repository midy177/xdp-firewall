use super::refresh::TempBanCleanup;
use crate::{
    db::entities::{geo_country_policy, geo_ip_prefix, policy_version, temp_ban},
    intelligence::geo,
    policy::model::DEFAULT_POLICY_NAME,
};
use anyhow::Result;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait, QueryFilter,
    QueryOrder, TransactionTrait,
};

mod snapshot;

pub(super) use snapshot::{build_policy_update, load_xds_snapshot};

pub(super) async fn latest_version(db: &DatabaseConnection) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

pub(super) async fn cleanup_expired_temp_bans(
    db: &DatabaseConnection,
) -> Result<(u64, Option<i64>)> {
    let now = chrono::Utc::now().naive_utc();
    let (deleted, version) = db
        .transaction::<_, (u64, Option<i64>), DbErr>(|txn| {
            Box::pin(async move {
                let deleted = temp_ban::Entity::delete_many()
                    .filter(temp_ban::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
                    .filter(temp_ban::Column::ExpiresAt.lte(now))
                    .exec(txn)
                    .await?
                    .rows_affected;
                let version = next_version_after_temp_ban_delete(txn, deleted).await?;
                Ok((deleted, version))
            })
        })
        .await?;
    Ok((deleted, version))
}

async fn next_version_after_temp_ban_delete(
    txn: &DatabaseTransaction,
    deleted: u64,
) -> Result<Option<i64>, DbErr> {
    if deleted == 0 {
        return Ok(None);
    }
    Ok(Some(
        crate::db::next_policy_version_in_transaction(txn, DEFAULT_POLICY_NAME).await?,
    ))
}

pub(super) async fn geo_ip_lists_missing(db: &DatabaseConnection) -> Result<bool> {
    let rows = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Enabled.eq(true))
        .all(db)
        .await?;
    for row in rows {
        if geo_country_prefixes_missing(db, &row.country).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn geo_country_prefixes_missing(db: &DatabaseConnection, country: &str) -> Result<bool> {
    let country = geo::normalize_country(country)?;
    Ok(geo_ip_prefix::Entity::find()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .one(db)
        .await?
        .is_none())
}

pub(super) async fn enabled_geo_countries(db: &DatabaseConnection) -> Result<Vec<String>> {
    Ok(geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Enabled.eq(true))
        .order_by_asc(geo_country_policy::Column::Country)
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.country)
        .collect())
}
