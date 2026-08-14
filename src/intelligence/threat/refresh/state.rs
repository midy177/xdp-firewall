use super::ThreatSource;
use crate::{
    db::entities::{threat_prefix, threat_source, threat_source_state},
    policy::model::DEFAULT_POLICY_NAME,
};
use anyhow::Result;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::collections::{HashMap, HashSet};

pub(super) async fn load_enabled_threat_sources(
    db: &DatabaseConnection,
) -> Result<Vec<ThreatSource>> {
    threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(ThreatSource::try_from)
        .collect()
}

pub(super) async fn load_existing_threat_states(
    db: &DatabaseConnection,
) -> Result<HashMap<String, threat_source_state::Model>> {
    Ok(threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .all(db)
        .await?
        .into_iter()
        .map(|row| (row.source_name.clone(), row))
        .collect())
}

pub(super) async fn load_existing_threat_prefix_sources(
    db: &DatabaseConnection,
) -> Result<HashSet<String>> {
    Ok(threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.source_name)
        .collect())
}
