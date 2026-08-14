use crate::{db, db::entities::threat_source_state, policy::model::DEFAULT_POLICY_NAME};
use anyhow::Result;
use sea_orm::{DatabaseConnection, EntityTrait, TransactionTrait, sea_query::OnConflict};

use super::super::persisted;
use super::batch::ThreatRefreshBatch;

pub(super) async fn persist_threat_refresh_batch(
    db: &DatabaseConnection,
    batch: ThreatRefreshBatch,
) -> Result<()> {
    let txn = db.begin().await?;
    for (source_name, prefixes) in batch.changed_prefixes_by_source {
        persisted::persist_threat_source_prefixes(
            &txn,
            DEFAULT_POLICY_NAME,
            &source_name,
            &prefixes,
            batch.checked_at,
        )
        .await?;
    }
    for state in batch.states {
        upsert_threat_source_state(&txn, state).await?;
    }
    if batch.changed_source_count > 0 {
        db::next_policy_version_in_transaction(&txn, DEFAULT_POLICY_NAME).await?;
    }
    txn.commit().await?;
    Ok(())
}

async fn upsert_threat_source_state(
    txn: &sea_orm::DatabaseTransaction,
    state: threat_source_state::ActiveModel,
) -> Result<(), sea_orm::DbErr> {
    threat_source_state::Entity::insert(state)
        .on_conflict(threat_source_state_upsert_conflict())
        .exec_without_returning(txn)
        .await?;
    Ok(())
}

fn threat_source_state_upsert_conflict() -> OnConflict {
    OnConflict::columns([
        threat_source_state::Column::PolicyName,
        threat_source_state::Column::SourceName,
    ])
    .update_columns([
        threat_source_state::Column::Fingerprint,
        threat_source_state::Column::PrefixCount,
        threat_source_state::Column::LastCheckedAt,
        threat_source_state::Column::LastChangedAt,
        threat_source_state::Column::UpdatedAt,
    ])
    .to_owned()
}
