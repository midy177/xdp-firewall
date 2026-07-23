use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_dynamic_defense")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub policy_name: String,
    pub enabled: bool,
    pub ip_rate_limit_enabled: bool,
    pub ip_packets_per_second: Option<i32>,
    pub ip_burst: Option<i32>,
    pub flood_enabled: bool,
    pub flood_packets_per_second: Option<i32>,
    pub flood_burst: Option<i32>,
    pub flood_block_seconds: Option<i32>,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
