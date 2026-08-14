use super::super::query::TrustedCidrMatchQuery;
use crate::{
    control_plane::api::{ApiResult, normalize_cidr},
    db::entities::trusted_cidr,
    policy::model::DEFAULT_POLICY_NAME,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

pub(super) struct TrustedCidrDeleteTarget {
    cidr: String,
}

impl TrustedCidrDeleteTarget {
    pub(super) fn from_query(query: TrustedCidrMatchQuery) -> ApiResult<Self> {
        Ok(Self {
            cidr: normalize_cidr(&query.cidr)?,
        })
    }

    pub(super) fn select(&self) -> sea_orm::Select<trusted_cidr::Entity> {
        self.apply_filters(trusted_cidr::Entity::find())
    }

    pub(super) fn delete(&self) -> sea_orm::DeleteMany<trusted_cidr::Entity> {
        self.apply_filters(trusted_cidr::Entity::delete_many())
    }

    fn apply_filters<Q>(&self, query: Q) -> Q
    where
        Q: QueryFilter,
    {
        query
            .filter(trusted_cidr::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
            .filter(trusted_cidr::Column::Cidr.eq(&self.cidr))
    }
}
