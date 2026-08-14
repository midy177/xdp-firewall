use crate::db::entities::trusted_cidr;
use anyhow::Result;
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set};
use std::collections::HashSet;

pub(super) async fn reconcile_existing_trusted_cidrs(
    db: &impl ConnectionTrait,
    rows: Vec<trusted_cidr::Model>,
    desired: &HashSet<String>,
    now: chrono::NaiveDateTime,
) -> Result<u64> {
    let mut changed = 0_u64;
    for row in rows {
        if desired.contains(&row.cidr) {
            changed += enable_trusted_cidr_if_needed(db, row, now).await?;
        } else {
            changed += disable_trusted_cidr_if_needed(db, row, now).await?;
        }
    }
    Ok(changed)
}

async fn enable_trusted_cidr_if_needed(
    db: &impl ConnectionTrait,
    row: trusted_cidr::Model,
    now: chrono::NaiveDateTime,
) -> Result<u64> {
    if row.enabled {
        return Ok(0);
    }
    let mut active: trusted_cidr::ActiveModel = row.into();
    active.enabled = Set(true);
    active.updated_at = Set(now);
    active.update(db).await?;
    Ok(1)
}

async fn disable_trusted_cidr_if_needed(
    db: &impl ConnectionTrait,
    row: trusted_cidr::Model,
    now: chrono::NaiveDateTime,
) -> Result<u64> {
    if !row.enabled {
        return Ok(0);
    }
    let mut active: trusted_cidr::ActiveModel = row.into();
    active.enabled = Set(false);
    active.updated_at = Set(now);
    active.update(db).await?;
    Ok(1)
}

pub(super) async fn insert_missing_trusted_cidrs(
    db: &impl ConnectionTrait,
    policy: &str,
    cidrs: Vec<String>,
    existing: &HashSet<String>,
    now: chrono::NaiveDateTime,
) -> Result<u64> {
    let mut inserted = 0_u64;
    for cidr in cidrs {
        if existing.contains(&cidr) {
            continue;
        }
        trusted_cidr::ActiveModel {
            policy_name: Set(policy.to_string()),
            enabled: Set(true),
            cidr: Set(cidr),
            comment: Set(Some("initialized from API CLI/env".to_string())),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(db)
        .await?;
        inserted += 1;
    }
    Ok(inserted)
}
