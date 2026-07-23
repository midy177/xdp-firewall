use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_trusted_cidrs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub policy_name: String,
    pub enabled: bool,
    pub cidr: String,
    pub comment: Option<String>,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
