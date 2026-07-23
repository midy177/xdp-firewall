use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_threat_sources")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub policy_name: String,
    pub enabled: bool,
    pub name: String,
    pub url: String,
    pub format: String,
    pub min_score: Option<i32>,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
