use crate::db::entities::{policy_version, threat_prefix, threat_source};
use crate::policy::model::DEFAULT_POLICY_NAME;
use anyhow::Result;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::super::{persisted::persisted_prefixes, source_fetch::prefix_to_cidr};

pub(super) async fn current_policy_version(db: &DatabaseConnection) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

pub(super) async fn load_threat_sources_by_cidr(
    db: &DatabaseConnection,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let enabled_source_names = load_enabled_threat_source_names(db).await?;
    if enabled_source_names.is_empty() {
        return Ok(BTreeMap::new());
    }

    let rows = threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_prefix::Column::SourceName.is_in(enabled_source_names))
        .order_by_asc(threat_prefix::Column::SourceName)
        .all(db)
        .await?;

    let mut sources_by_cidr = BTreeMap::<String, BTreeSet<String>>::new();
    for row in rows {
        for prefix in persisted_prefixes(&row)? {
            sources_by_cidr
                .entry(prefix_to_cidr(&prefix))
                .or_default()
                .insert(row.source_name.clone());
        }
    }
    Ok(sources_by_cidr)
}

async fn load_enabled_threat_source_names(db: &DatabaseConnection) -> Result<HashSet<String>> {
    Ok(threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.name)
        .collect())
}
