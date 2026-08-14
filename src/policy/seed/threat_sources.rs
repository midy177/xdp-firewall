use crate::{db::entities::threat_source, intelligence::threat};
use anyhow::Result;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, sea_query::OnConflict};
use std::collections::HashSet;

pub(super) async fn insert_builtin_threat_sources(
    db: &impl ConnectionTrait,
    policy_name: &str,
) -> Result<u64> {
    let now = chrono::Utc::now().naive_utc();
    let existing_names = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .all(db)
        .await?
        .into_iter()
        .map(|source| source.name)
        .collect::<HashSet<_>>();
    let mut inserted = 0_u64;
    for source in threat::BUILTIN_THREAT_SOURCES {
        if existing_names.contains(source.name) {
            continue;
        }
        let model = threat_source::ActiveModel {
            policy_name: Set(policy_name.to_string()),
            enabled: Set(true),
            name: Set(source.name.to_string()),
            url: Set(source.url.to_string()),
            format: Set(source.format.to_string()),
            min_score: Set(source.min_score),
            updated_at: Set(now),
            ..Default::default()
        };
        threat_source::Entity::insert(model)
            .on_conflict(
                OnConflict::columns([
                    threat_source::Column::PolicyName,
                    threat_source::Column::Name,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(db)
            .await?;
        inserted += 1;
    }
    Ok(inserted)
}
