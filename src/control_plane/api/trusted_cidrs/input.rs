use super::ApiResult;
use crate::{db::entities::trusted_cidr, policy::model::DEFAULT_POLICY_NAME};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct CreateTrustedCidrRequest {
    pub(super) enabled: Option<bool>,
    pub(super) cidr: String,
    pub(super) comment: Option<String>,
}

pub(super) struct TrustedCidrUpsert {
    pub(super) row: trusted_cidr::Model,
    pub(super) inserted: bool,
    pub(super) active_changed: bool,
}

pub(super) async fn upsert<C>(
    db: &C,
    request: CreateTrustedCidrRequest,
    normalized_cidr: Option<String>,
) -> ApiResult<TrustedCidrUpsert>
where
    C: ConnectionTrait,
{
    let cidr = match normalized_cidr {
        Some(cidr) => cidr,
        None => super::super::normalize_cidr(&request.cidr)?,
    };
    let now = chrono::Utc::now().naive_utc();
    let enabled = request.enabled.unwrap_or(true);
    let comment = request.comment;
    let existing = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(trusted_cidr::Column::Cidr.eq(&cidr))
        .one(db)
        .await?;

    let Some(existing) = existing else {
        let row = trusted_cidr::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(enabled),
            cidr: Set(cidr),
            comment: Set(comment),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(db)
        .await?;
        return Ok(TrustedCidrUpsert {
            row,
            inserted: true,
            active_changed: enabled,
        });
    };
    if trusted_cidr_fields_match(&existing, enabled, &comment) {
        return Ok(TrustedCidrUpsert {
            row: existing,
            inserted: false,
            active_changed: false,
        });
    }

    let active_changed = trusted_cidr_active_changed(&existing, enabled, &comment);
    let mut active: trusted_cidr::ActiveModel = existing.into();
    active.enabled = Set(enabled);
    active.comment = Set(comment);
    active.updated_at = Set(now);
    let row = active.update(db).await?;
    Ok(TrustedCidrUpsert {
        row,
        inserted: false,
        active_changed,
    })
}

fn trusted_cidr_fields_match(
    row: &trusted_cidr::Model,
    enabled: bool,
    comment: &Option<String>,
) -> bool {
    row.enabled == enabled && row.comment == *comment
}

fn trusted_cidr_active_changed(
    row: &trusted_cidr::Model,
    enabled: bool,
    comment: &Option<String>,
) -> bool {
    if row.enabled != enabled {
        return true;
    }
    enabled && row.comment != *comment
}
