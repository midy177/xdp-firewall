use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_threat_source_states")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub policy_name: String,
    pub source_name: String,
    pub fingerprint: String,
    pub prefix_count: i32,
    pub last_checked_at: NaiveDateTime,
    pub last_changed_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
