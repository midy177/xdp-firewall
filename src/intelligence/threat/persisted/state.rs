use crate::{
    db::entities::{threat_prefix, threat_source, threat_source_state},
    policy::model::DEFAULT_POLICY_NAME,
};
use anyhow::Result;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

pub async fn enabled_threat_source_states_missing(db: &DatabaseConnection) -> Result<bool> {
    let sources = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?;
    for source in sources {
        if threat_source_state_missing(db, &source.name).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn threat_source_state_missing(db: &DatabaseConnection, source_name: &str) -> Result<bool> {
    Ok(!has_threat_source_state(db, source_name).await?
        || !has_threat_source_prefixes(db, source_name).await?)
}

async fn has_threat_source_state(db: &DatabaseConnection, source_name: &str) -> Result<bool> {
    Ok(threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source_state::Column::SourceName.eq(source_name))
        .one(db)
        .await?
        .is_some())
}

async fn has_threat_source_prefixes(db: &DatabaseConnection, source_name: &str) -> Result<bool> {
    Ok(threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_prefix::Column::SourceName.eq(source_name))
        .one(db)
        .await?
        .is_some())
}
