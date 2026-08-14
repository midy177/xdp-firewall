use crate::db::entities::node;
use crate::policy::model::DEFAULT_POLICY_NAME;
use anyhow::{Result, bail};
use chrono::NaiveDateTime;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

pub const DEFAULT_UNHEALTHY_NODE_AFTER_SECONDS: i64 = 300;
pub const NODE_MAINTENANCE_INTERVAL_SECONDS: u64 = 60;
const MAX_UNHEALTHY_NODE_AFTER_SECONDS: i64 = 31_536_000;

pub fn normalize_unhealthy_node_after_seconds(value: Option<i64>) -> Result<i64> {
    let value = value.unwrap_or(DEFAULT_UNHEALTHY_NODE_AFTER_SECONDS);
    if value <= 0 {
        bail!("max_age_seconds must be greater than 0");
    }
    if value > MAX_UNHEALTHY_NODE_AFTER_SECONDS {
        bail!("max_age_seconds must be at most {MAX_UNHEALTHY_NODE_AFTER_SECONDS}");
    }
    Ok(value)
}

#[must_use]
pub fn seconds_since_seen(last_seen_at: NaiveDateTime, now: NaiveDateTime) -> i64 {
    now.signed_duration_since(last_seen_at).num_seconds().max(0)
}

#[must_use]
pub fn sync_status(
    raw_status: &str,
    last_applied_version: i64,
    current_policy_version: i64,
    last_seen_at: NaiveDateTime,
    now: NaiveDateTime,
    max_age_seconds: i64,
) -> String {
    if seconds_since_seen(last_seen_at, now) > max_age_seconds {
        return "offline".to_string();
    }
    let status = raw_status.trim().to_ascii_lowercase();
    if status != "ok" {
        return status;
    }
    if last_applied_version < current_policy_version {
        return "stale".to_string();
    }
    "ok".to_string()
}

pub async fn prune_unhealthy_nodes(db: &DatabaseConnection, max_age_seconds: i64) -> Result<u64> {
    let max_age_seconds = normalize_unhealthy_node_after_seconds(Some(max_age_seconds))?;
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(max_age_seconds);
    let deleted = node::Entity::delete_many()
        .filter(node::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(node::Column::LastSeenAt.lte(cutoff))
        .exec(db)
        .await?
        .rows_affected;
    Ok(deleted)
}
