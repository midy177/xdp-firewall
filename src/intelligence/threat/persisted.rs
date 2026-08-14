use super::{ThreatPrefix, source_fetch::normalize_prefixes};
use crate::{db::entities::threat_prefix, policy::model::DEFAULT_POLICY_NAME};
use anyhow::Result;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set,
};

mod cidrs;
mod state;

use cidrs::cidrs_json_from_prefixes;
pub(super) use cidrs::persisted_prefixes;
pub use state::enabled_threat_source_states_missing;

pub async fn load_persisted_threat_prefixes(
    db: &DatabaseConnection,
    policy_name: &str,
    source_names: &[String],
) -> Result<Vec<ThreatPrefix>> {
    if source_names.is_empty() {
        return Ok(Vec::new());
    }
    let rows = threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(policy_name))
        .filter(threat_prefix::Column::SourceName.is_in(source_names.iter().cloned()))
        .order_by_asc(threat_prefix::Column::SourceName)
        .all(db)
        .await?;
    let mut prefixes = Vec::new();
    for row in rows {
        prefixes.extend(persisted_prefixes(&row)?);
    }
    Ok(normalize_prefixes(prefixes))
}

pub async fn delete_persisted_threat_prefixes_by_name<'a, I>(
    db: &impl ConnectionTrait,
    names: I,
) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let names = names.into_iter().collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(());
    }
    threat_prefix::Entity::delete_many()
        .filter(threat_prefix::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_prefix::Column::SourceName.is_in(names))
        .exec(db)
        .await?;
    Ok(())
}

pub(super) async fn persist_threat_source_prefixes(
    db: &impl ConnectionTrait,
    policy_name: &str,
    source_name: &str,
    prefixes: &[ThreatPrefix],
    now: chrono::NaiveDateTime,
) -> Result<()> {
    let cidrs_json = cidrs_json_from_prefixes(prefixes);
    threat_prefix::Entity::delete_many()
        .filter(threat_prefix::Column::PolicyName.eq(policy_name))
        .filter(threat_prefix::Column::SourceName.eq(source_name))
        .exec(db)
        .await?;
    threat_prefix::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        source_name: Set(source_name.to_string()),
        cidrs_json: Set(cidrs_json),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}
