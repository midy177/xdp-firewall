use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_geo_ip_prefixes")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub country: String,
    // Large countries aggregate to >64 KiB of CIDR JSON; migrations promote
    // this to MEDIUMTEXT on MySQL (other backends' TEXT is unlimited).
    #[sea_orm(column_type = "Text")]
    pub cidrs_json: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
