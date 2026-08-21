use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_nodes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: String,
    pub policy_name: String,
    pub interface_name: String,
    // Unbounded joined IP list; migrations promote to TEXT on MySQL.
    #[sea_orm(column_type = "Text")]
    pub interface_ips: String,
    pub last_seen_at: NaiveDateTime,
    pub last_applied_version: i64,
    pub status: String,
    // Truncated to 512 bytes upstream, which exceeds MySQL varchar(255).
    #[sea_orm(column_type = "Text")]
    pub error: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
