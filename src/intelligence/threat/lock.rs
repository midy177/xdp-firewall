use crate::{
    db::entities::threat_source_state, intelligence::refresh_lock,
    policy::model::DEFAULT_POLICY_NAME,
};
use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, sea_query::OnConflict,
};
use tracing::warn;

const REFRESH_LOCK_POLICY_NAME: &str = "__threat_refresh_lock__";
const REFRESH_LOCK_SOURCE_NAME: &str = DEFAULT_POLICY_NAME;
const REFRESH_LOCK_STALE_SECONDS: i64 = 900;

pub(super) struct ThreatRefreshDbLock {
    db: DatabaseConnection,
    owner: String,
}

impl ThreatRefreshDbLock {
    pub(super) async fn try_acquire(db: &DatabaseConnection) -> Result<Option<Self>> {
        let now = chrono::Utc::now().naive_utc();
        let owner = refresh_lock::lock_owner(now);
        ensure_threat_refresh_lock_row(db, now).await?;
        let existing = load_threat_refresh_lock_row(db).await?;
        if threat_refresh_lock_is_busy(&existing, now) {
            return Ok(None);
        }

        let acquired = mark_threat_refresh_lock_running(db, &existing, now, &owner).await?;
        Ok(acquired.then(|| Self {
            db: db.clone(),
            owner,
        }))
    }
}

impl Drop for ThreatRefreshDbLock {
    fn drop(&mut self) {
        let db = self.db.clone();
        let owner = self.owner.clone();
        tokio::spawn(async move {
            if let Err(err) = release_threat_refresh_lock(&db, owner).await {
                warn!(error = %err, "failed to release threat source refresh database lock");
            }
        });
    }
}

async fn ensure_threat_refresh_lock_row(
    db: &DatabaseConnection,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    threat_source_state::Entity::insert(threat_source_state::ActiveModel {
        policy_name: Set(REFRESH_LOCK_POLICY_NAME.to_string()),
        source_name: Set(REFRESH_LOCK_SOURCE_NAME.to_string()),
        fingerprint: Set("idle".to_string()),
        prefix_count: Set(0),
        last_checked_at: Set(now),
        last_changed_at: Set(None),
        updated_at: Set(now),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::columns([
            threat_source_state::Column::PolicyName,
            threat_source_state::Column::SourceName,
        ])
        .do_nothing()
        .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    Ok(())
}

async fn load_threat_refresh_lock_row(
    db: &DatabaseConnection,
) -> Result<threat_source_state::Model> {
    threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq(REFRESH_LOCK_POLICY_NAME))
        .filter(threat_source_state::Column::SourceName.eq(REFRESH_LOCK_SOURCE_NAME))
        .one(db)
        .await?
        .context("failed to initialize threat source refresh database lock")
}

fn threat_refresh_lock_is_busy(
    existing: &threat_source_state::Model,
    now: chrono::NaiveDateTime,
) -> bool {
    let is_running = existing.fingerprint.starts_with("running:");
    is_running
        && refresh_lock::lease_is_fresh(
            existing.last_checked_at,
            existing.updated_at,
            now,
            REFRESH_LOCK_STALE_SECONDS,
        )
}

async fn mark_threat_refresh_lock_running(
    db: &DatabaseConnection,
    existing: &threat_source_state::Model,
    now: chrono::NaiveDateTime,
    owner: &str,
) -> Result<bool> {
    let updated = threat_source_state::Entity::update_many()
        .filter(threat_source_state::Column::PolicyName.eq(REFRESH_LOCK_POLICY_NAME))
        .filter(threat_source_state::Column::SourceName.eq(REFRESH_LOCK_SOURCE_NAME))
        .filter(threat_source_state::Column::LastCheckedAt.eq(existing.last_checked_at))
        .col_expr(
            threat_source_state::Column::Fingerprint,
            sea_orm::sea_query::Expr::value(format!("running:{owner}")),
        )
        .col_expr(
            threat_source_state::Column::LastCheckedAt,
            sea_orm::sea_query::Expr::value(now),
        )
        .col_expr(
            threat_source_state::Column::LastChangedAt,
            sea_orm::sea_query::Expr::value(Some(now)),
        )
        .exec(db)
        .await?;
    Ok(updated.rows_affected > 0)
}

async fn release_threat_refresh_lock(db: &DatabaseConnection, owner: String) -> Result<()> {
    threat_source_state::Entity::update_many()
        .filter(threat_source_state::Column::PolicyName.eq(REFRESH_LOCK_POLICY_NAME))
        .filter(threat_source_state::Column::SourceName.eq(REFRESH_LOCK_SOURCE_NAME))
        .filter(threat_source_state::Column::Fingerprint.eq(format!("running:{owner}")))
        .col_expr(
            threat_source_state::Column::Fingerprint,
            sea_orm::sea_query::Expr::value("idle"),
        )
        .col_expr(
            threat_source_state::Column::LastCheckedAt,
            sea_orm::sea_query::Expr::value(chrono::Utc::now().naive_utc()),
        )
        .exec(db)
        .await?;
    Ok(())
}
