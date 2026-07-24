use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_geo_ip_list_states")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub country: String,
    pub url: String,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub prefix_count: i32,
    pub last_checked_at: NaiveDateTime,
    pub last_downloaded_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
