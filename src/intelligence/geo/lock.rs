use super::IPDENY_ROOT;
use crate::db::entities::geo_ip_list_state;
use crate::intelligence::refresh_lock;
use anyhow::{Result, bail};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, sea_query::OnConflict,
};
use tracing::warn;

const REFRESH_LOCK_COUNTRY: &str = "__refresh_lock__";
const REFRESH_LOCK_STALE_SECONDS: i64 = 30 * 60;

pub(super) struct GeoRefreshDbLock {
    db: DatabaseConnection,
    owner: String,
}

impl GeoRefreshDbLock {
    pub(super) async fn try_acquire(db: &DatabaseConnection) -> Result<Option<Self>> {
        let now = chrono::Utc::now().naive_utc();
        let owner = refresh_lock::lock_owner(now);
        ensure_lock_row(db, now).await?;
        let Some(existing) = load_lock_row(db).await? else {
            bail!("failed to initialize country IP refresh database lock");
        };
        if lock_is_busy(&existing, now) {
            return Ok(None);
        }
        mark_lock_running(db, &existing, &owner, now).await
    }
}

impl Drop for GeoRefreshDbLock {
    fn drop(&mut self) {
        let db = self.db.clone();
        let owner = self.owner.clone();
        tokio::spawn(async move {
            if let Err(err) = release_lock(&db, owner).await {
                warn!(error = %err, "failed to release country IP refresh database lock");
            }
        });
    }
}

async fn ensure_lock_row(db: &DatabaseConnection, now: chrono::NaiveDateTime) -> Result<()> {
    geo_ip_list_state::Entity::insert(geo_ip_list_state::ActiveModel {
        country: Set(REFRESH_LOCK_COUNTRY.to_string()),
        url: Set(IPDENY_ROOT.to_string()),
        last_modified: Set(Some("idle".to_string())),
        etag: Set(None),
        prefix_count: Set(0),
        last_checked_at: Set(now),
        last_downloaded_at: Set(None),
        updated_at: Set(now),
        ..Default::default()
    })
    .on_conflict(
        // `do_nothing()` renders invalid SQL on MySQL (sea-query emits a
        // trailing " IGNORE"); self-assigning the conflict target column is a
        // cross-database no-op that leaves an existing lock row untouched.
        OnConflict::column(geo_ip_list_state::Column::Country)
            .update_columns([geo_ip_list_state::Column::Country])
            .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    Ok(())
}

async fn load_lock_row(db: &DatabaseConnection) -> Result<Option<geo_ip_list_state::Model>> {
    Ok(geo_ip_list_state::Entity::find()
        .filter(geo_ip_list_state::Column::Country.eq(REFRESH_LOCK_COUNTRY))
        .one(db)
        .await?)
}

fn lock_is_busy(existing: &geo_ip_list_state::Model, now: chrono::NaiveDateTime) -> bool {
    let is_running = existing.last_modified.as_deref() == Some("running");
    is_running
        && refresh_lock::lease_is_fresh(
            existing.last_checked_at,
            existing.updated_at,
            now,
            REFRESH_LOCK_STALE_SECONDS,
        )
}

async fn mark_lock_running(
    db: &DatabaseConnection,
    existing: &geo_ip_list_state::Model,
    owner: &str,
    now: chrono::NaiveDateTime,
) -> Result<Option<GeoRefreshDbLock>> {
    let updated = geo_ip_list_state::Entity::update_many()
        .filter(geo_ip_list_state::Column::Country.eq(REFRESH_LOCK_COUNTRY))
        .filter(geo_ip_list_state::Column::LastCheckedAt.eq(existing.last_checked_at))
        .col_expr(
            geo_ip_list_state::Column::LastModified,
            sea_orm::sea_query::Expr::value("running"),
        )
        .col_expr(
            geo_ip_list_state::Column::Etag,
            sea_orm::sea_query::Expr::value(owner.to_string()),
        )
        .col_expr(
            geo_ip_list_state::Column::LastCheckedAt,
            sea_orm::sea_query::Expr::value(now),
        )
        .exec(db)
        .await?;
    Ok((updated.rows_affected > 0).then(|| GeoRefreshDbLock {
        db: db.clone(),
        owner: owner.to_string(),
    }))
}

async fn release_lock(db: &DatabaseConnection, owner: String) -> Result<()> {
    geo_ip_list_state::Entity::update_many()
        .filter(geo_ip_list_state::Column::Country.eq(REFRESH_LOCK_COUNTRY))
        .filter(geo_ip_list_state::Column::Etag.eq(owner))
        .col_expr(
            geo_ip_list_state::Column::LastModified,
            sea_orm::sea_query::Expr::value("idle"),
        )
        .col_expr(
            geo_ip_list_state::Column::Etag,
            sea_orm::sea_query::Expr::value(Option::<String>::None),
        )
        .col_expr(
            geo_ip_list_state::Column::LastCheckedAt,
            sea_orm::sea_query::Expr::value(chrono::Utc::now().naive_utc()),
        )
        .exec(db)
        .await?;
    Ok(())
}
