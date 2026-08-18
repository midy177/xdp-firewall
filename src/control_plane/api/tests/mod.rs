use super::*;
use crate::db::entities::{dynamic_defense, firewall_rule, node};
use crate::intelligence::threat;
use crate::policy::firewall;
use crate::policy::model::{DEFAULT_POLICY_NAME, L4Protocol};
use axum::{
    Router,
    http::{Method, StatusCode},
};
use sea_orm::EntityTrait;
use serde_json::{Value, json};
mod batch_tests;
mod config_resources_tests;
mod dynamic_defense_tests;
mod dynamic_rate_limits_tests;
mod firewall_rules_tests;
mod helpers;
mod limiter_tests;
mod nodes_tests;
mod standby_tests;
mod temp_bans_tests;
mod threat_sources_tests;

use helpers::*;
