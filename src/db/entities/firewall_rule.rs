use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize)]
#[sea_orm(table_name = "firewall_rules")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub policy_name: String,
    #[sea_orm(column_type = "String(StringLen::N(128))")]
    pub rule_key: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: String,
    pub cidr: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    #[sea_orm(column_type = "Text")]
    pub comment: Option<String>,
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub fn generated_rule_key(
    priority: i32,
    action: &str,
    cidr: &str,
    protocol: Option<&str>,
    port: Option<i32>,
) -> String {
    let protocol = protocol.unwrap_or("any");
    let port = port.map_or_else(String::new, |value| value.to_string());
    let canonical = format!(
        "priority={priority}\naction={action}\ncidr={cidr}\nprotocol={protocol}\nport={port}\n"
    );
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
