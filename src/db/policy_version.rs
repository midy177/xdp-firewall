use super::entities;
use anyhow::Result;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait,
    QueryFilter, Set,
};

pub async fn next_policy_version(db: &DatabaseConnection, policy_name: &str) -> Result<i64> {
    use entities::policy_version::{ActiveModel, Entity};

    let current = Entity::find()
        .filter(entities::policy_version::Column::PolicyName.eq(policy_name))
        .one(db)
        .await?;
    let next_version = current.as_ref().map_or(1, |row| row.version + 1);
    if let Some(row) = current {
        let mut active: ActiveModel = row.into();
        active.version = Set(next_version);
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        active.update(db).await?;
    } else {
        ActiveModel {
            policy_name: Set(policy_name.to_string()),
            version: Set(next_version),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(db)
        .await?;
    }
    Ok(next_version)
}

pub async fn next_policy_version_in_transaction(
    txn: &DatabaseTransaction,
    policy_name: &str,
) -> std::result::Result<i64, DbErr> {
    use entities::policy_version::{ActiveModel, Entity};

    let current = Entity::find()
        .filter(entities::policy_version::Column::PolicyName.eq(policy_name))
        .one(txn)
        .await?;
    let next_version = current.as_ref().map_or(1, |row| row.version + 1);
    if let Some(row) = current {
        let mut active: ActiveModel = row.into();
        active.version = Set(next_version);
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        active.update(txn).await?;
    } else {
        ActiveModel {
            policy_name: Set(policy_name.to_string()),
            version: Set(next_version),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(txn)
        .await?;
    }
    Ok(next_version)
}
