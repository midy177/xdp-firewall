use crate::cli::{SeedExampleArgs, ShowPolicyArgs};
use crate::db::entities::{
    dynamic_defense, dynamic_rate_limit, firewall_rule, geo_country_policy, policy_version,
    temp_ban, threat_prefix, threat_source, threat_source_state, trusted_cidr,
};
use crate::{geo, threat};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};
use tracing::info;

pub const DEFAULT_POLICY_NAME: &str = "edge";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub priority: i32,
    pub action: RuleAction,
    pub cidr: IpNet,
    pub protocol: L4Protocol,
    pub port: Option<u16>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoCountryPolicy {
    pub country: String,
    pub action: RuleAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpPrefixPolicy {
    pub cidr: IpNet,
    pub country: String,
}

pub const DEFAULT_IP_RATE_LIMIT_PPS: u32 = 5_000;
pub const DEFAULT_IP_RATE_LIMIT_BURST: u32 = 10_000;
pub const DEFAULT_FLOOD_PPS: u32 = 20_000;
pub const DEFAULT_FLOOD_BURST: u32 = 40_000;
pub const DEFAULT_FLOOD_BLOCK_SECONDS: u32 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicDefensePolicy {
    pub enabled: bool,
    pub ip_rate_limit_enabled: bool,
    pub ip_packets_per_second: Option<u32>,
    pub ip_burst: Option<u32>,
    pub flood_enabled: bool,
    pub flood_packets_per_second: Option<u32>,
    pub flood_burst: Option<u32>,
    pub flood_block_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicRateLimitPolicy {
    pub priority: i32,
    pub protocol: L4Protocol,
    pub port: Option<u16>,
    pub packets_per_second: u32,
    pub burst: u32,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempBanPolicy {
    pub ip: IpAddr,
    pub protocol: L4Protocol,
    pub port: Option<u16>,
    pub expires_at: chrono::NaiveDateTime,
    pub comment: Option<String>,
}

impl Default for DynamicDefensePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            ip_rate_limit_enabled: true,
            ip_packets_per_second: Some(DEFAULT_IP_RATE_LIMIT_PPS),
            ip_burst: Some(DEFAULT_IP_RATE_LIMIT_BURST),
            flood_enabled: true,
            flood_packets_per_second: Some(DEFAULT_FLOOD_PPS),
            flood_burst: Some(DEFAULT_FLOOD_BURST),
            flood_block_seconds: Some(DEFAULT_FLOOD_BLOCK_SECONDS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCidrPolicy {
    pub cidr: IpNet,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    #[serde(default = "default_policy_name", skip_serializing)]
    pub policy_name: String,
    pub version: i64,
    pub rules: Vec<FirewallRule>,
    pub geo_countries: Vec<GeoCountryPolicy>,
    #[serde(default)]
    pub geo_prefixes: Vec<GeoIpPrefixPolicy>,
    #[serde(default)]
    pub temp_bans: Vec<TempBanPolicy>,
    pub dynamic_defense: DynamicDefensePolicy,
    pub dynamic_rate_limits: Vec<DynamicRateLimitPolicy>,
    pub trusted_cidrs: Vec<TrustedCidrPolicy>,
    pub threat_sources: Vec<threat::ThreatSource>,
    #[serde(default)]
    pub threat_prefixes: Vec<threat::ThreatPrefix>,
}

fn default_policy_name() -> String {
    DEFAULT_POLICY_NAME.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub version: i64,
    pub trusted_prefixes: Vec<XdpTrustedPrefix>,
    pub rules: Vec<XdpPrefixRule>,
    pub country_rules: Vec<XdpCountryRule>,
    pub temp_bans: Vec<XdpTempBan>,
    pub dynamic_defense: XdpDynamicDefense,
    pub dynamic_rate_limits: Vec<XdpDynamicRateLimit>,
    pub geo_prefixes: Vec<XdpGeoPrefix>,
    pub threat_prefixes: Vec<XdpPrefixRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpTrustedPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpPrefixRule {
    pub addr: IpAddr,
    pub prefix: u8,
    pub priority: i32,
    pub action: RuleAction,
    pub protocol: L4Protocol,
    pub port: u16,
    pub source: XdpRuleSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpRuleSource {
    FirewallRule,
    ThreatIntel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpGeoPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
    pub country: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpCountryRule {
    pub country: u16,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpTempBan {
    pub addr: IpAddr,
    pub protocol: L4Protocol,
    pub port: u16,
    pub expires_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XdpDynamicDefense {
    pub enabled: bool,
    pub ip_rate_limit_enabled: bool,
    pub ip_packets_per_second: u32,
    pub ip_burst: u32,
    pub flood_enabled: bool,
    pub flood_packets_per_second: u32,
    pub flood_burst: u32,
    pub flood_block_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpDynamicRateLimit {
    pub protocol: L4Protocol,
    pub port: u16,
    pub packets_per_second: u32,
    pub burst: u32,
}

pub async fn load_policy(db: &DatabaseConnection, policy_name: &str) -> Result<PolicySnapshot> {
    load_policy_with_geo_prefixes(db, policy_name, true).await
}

pub async fn load_policy_without_geo_prefixes(
    db: &DatabaseConnection,
    policy_name: &str,
) -> Result<PolicySnapshot> {
    load_policy_with_geo_prefixes(db, policy_name, false).await
}

async fn load_policy_with_geo_prefixes(
    db: &DatabaseConnection,
    policy_name: &str,
    include_geo_prefixes: bool,
) -> Result<PolicySnapshot> {
    let version = policy_version::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .map_or(0, |row| row.version);

    let rules = firewall_rule::Entity::find()
        .filter(firewall_rule::Column::PolicyName.eq(policy_name))
        .filter(firewall_rule::Column::Enabled.eq(true))
        .order_by_asc(firewall_rule::Column::Priority)
        .all(db)
        .await?
        .into_iter()
        .map(parse_rule)
        .collect::<Result<Vec<_>>>()?;

    let geo_countries = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(policy_name))
        .filter(geo_country_policy::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(parse_geo_country_policy)
        .collect::<Result<Vec<_>>>()?;
    let geo_country_codes = geo_countries
        .iter()
        .map(|policy| policy.country.clone())
        .collect::<Vec<_>>();
    let geo_prefixes = if include_geo_prefixes {
        geo::load_persisted_geo_prefixes(db, &geo_country_codes)
            .await?
            .into_iter()
            .map(|prefix| {
                Ok(GeoIpPrefixPolicy {
                    cidr: geo_prefix_to_ipnet(prefix.addr, prefix.prefix)?,
                    country: geo::decode_country(prefix.country)
                        .with_context(|| "invalid persisted geo country code")?,
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    let threat_sources = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(threat::ThreatSource::try_from)
        .collect::<Result<Vec<_>>>()?;
    let threat_source_names = threat_sources
        .iter()
        .map(|source| source.name.clone())
        .collect::<Vec<_>>();
    let threat_prefixes =
        threat::load_persisted_threat_prefixes(db, policy_name, &threat_source_names).await?;

    let dynamic_defense = dynamic_defense::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .map(parse_dynamic_defense)
        .transpose()?
        .unwrap_or_default();
    validate_dynamic_defense_policy(&dynamic_defense)?;
    let dynamic_rate_limits = dynamic_rate_limit::Entity::find()
        .filter(dynamic_rate_limit::Column::PolicyName.eq(policy_name))
        .filter(dynamic_rate_limit::Column::Enabled.eq(true))
        .order_by_asc(dynamic_rate_limit::Column::Priority)
        .all(db)
        .await?
        .into_iter()
        .map(parse_dynamic_rate_limit)
        .collect::<Result<Vec<_>>>()?;
    let now = chrono::Utc::now().naive_utc();
    let temp_bans = temp_ban::Entity::find()
        .filter(temp_ban::Column::PolicyName.eq(policy_name))
        .filter(temp_ban::Column::ExpiresAt.gt(now))
        .order_by_asc(temp_ban::Column::ExpiresAt)
        .all(db)
        .await?
        .into_iter()
        .map(parse_temp_ban)
        .collect::<Result<Vec<_>>>()?;
    let trusted_cidrs = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(policy_name))
        .filter(trusted_cidr::Column::Enabled.eq(true))
        .order_by_asc(trusted_cidr::Column::Cidr)
        .all(db)
        .await?
        .into_iter()
        .map(parse_trusted_cidr)
        .collect::<Result<Vec<_>>>()?;

    Ok(PolicySnapshot {
        policy_name: policy_name.to_string(),
        version,
        rules,
        geo_countries,
        geo_prefixes,
        temp_bans,
        dynamic_defense,
        dynamic_rate_limits,
        trusted_cidrs,
        threat_sources,
        threat_prefixes,
    })
}

pub async fn ensure_builtin_policy(db: &DatabaseConnection, policy_name: &str) -> Result<()> {
    if policy_version::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .is_some()
    {
        let inserted = insert_builtin_threat_sources(db, policy_name).await?;
        if inserted > 0 {
            let version = crate::db::next_policy_version(db, policy_name).await?;
            info!(
                policy = %policy_name,
                version,
                inserted_builtin_threat_sources = inserted,
                "added missing built-in threat intelligence sources"
            );
        }
        return Ok(());
    }

    insert_default_dynamic_defense(db, policy_name).await?;
    let inserted = insert_builtin_threat_sources(db, policy_name).await?;
    let version = crate::db::next_policy_version(db, policy_name).await?;
    info!(
        policy = %policy_name,
        version,
        inserted_builtin_threat_sources = inserted,
        "initialized policy with built-in threat intelligence"
    );
    Ok(())
}

pub async fn compile_policy(snapshot: &PolicySnapshot) -> Result<CompiledPolicy> {
    validate_dynamic_defense_policy(&snapshot.dynamic_defense)?;
    for limit in &snapshot.dynamic_rate_limits {
        validate_dynamic_rate_limit_policy(limit)?;
    }
    let geo_prefixes = snapshot
        .geo_prefixes
        .iter()
        .map(|prefix| {
            let (addr, len) = match prefix.cidr {
                IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
                IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
            };
            Ok(XdpGeoPrefix {
                addr,
                prefix: len,
                country: geo::encode_country(&prefix.country)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let threat_prefixes = snapshot
        .threat_prefixes
        .iter()
        .map(|prefix| XdpPrefixRule {
            addr: prefix.addr,
            prefix: prefix.prefix,
            priority: i32::MIN,
            action: RuleAction::Deny,
            protocol: L4Protocol::Any,
            port: 0,
            source: XdpRuleSource::ThreatIntel,
        })
        .collect();
    let trusted_prefixes = snapshot
        .trusted_cidrs
        .iter()
        .map(|trusted| {
            let (addr, prefix) = match trusted.cidr {
                IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
                IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
            };
            XdpTrustedPrefix { addr, prefix }
        })
        .collect();
    let rules = snapshot
        .rules
        .iter()
        .map(|rule| {
            let (addr, prefix) = match rule.cidr {
                IpNet::V4(net) => (IpAddr::V4(net.network()), net.prefix_len()),
                IpNet::V6(net) => (IpAddr::V6(net.network()), net.prefix_len()),
            };
            XdpPrefixRule {
                addr,
                prefix,
                priority: rule.priority,
                action: rule.action,
                protocol: rule.protocol,
                port: rule.port.unwrap_or(0),
                source: XdpRuleSource::FirewallRule,
            }
        })
        .collect();
    let country_rules = snapshot
        .geo_countries
        .iter()
        .map(|policy| {
            Ok(XdpCountryRule {
                country: geo::encode_country(&policy.country)?,
                action: policy.action,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let temp_bans = snapshot
        .temp_bans
        .iter()
        .filter(|ban| ban.expires_at > chrono::Utc::now().naive_utc())
        .map(|ban| XdpTempBan {
            addr: ban.ip,
            protocol: ban.protocol,
            port: ban.port.unwrap_or(0),
            expires_at: ban.expires_at,
        })
        .collect();
    let dynamic_defense = XdpDynamicDefense {
        enabled: snapshot.dynamic_defense.enabled,
        ip_rate_limit_enabled: snapshot.dynamic_defense.ip_rate_limit_enabled,
        ip_packets_per_second: snapshot.dynamic_defense.ip_packets_per_second.unwrap_or(0),
        ip_burst: snapshot.dynamic_defense.ip_burst.unwrap_or(0),
        flood_enabled: snapshot.dynamic_defense.flood_enabled,
        flood_packets_per_second: snapshot
            .dynamic_defense
            .flood_packets_per_second
            .unwrap_or(0),
        flood_burst: snapshot.dynamic_defense.flood_burst.unwrap_or(0),
        flood_block_seconds: snapshot.dynamic_defense.flood_block_seconds.unwrap_or(0),
    };
    let dynamic_rate_limits = snapshot
        .dynamic_rate_limits
        .iter()
        .map(|limit| XdpDynamicRateLimit {
            protocol: limit.protocol,
            port: limit.port.unwrap_or(0),
            packets_per_second: limit.packets_per_second,
            burst: limit.burst,
        })
        .collect();

    Ok(CompiledPolicy {
        version: snapshot.version,
        trusted_prefixes,
        rules,
        country_rules,
        temp_bans,
        dynamic_defense,
        dynamic_rate_limits,
        geo_prefixes,
        threat_prefixes,
    })
}

pub async fn seed_example_policy(db: &DatabaseConnection, args: SeedExampleArgs) -> Result<()> {
    let _ = args;
    let policy_name = DEFAULT_POLICY_NAME;
    firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    threat_source_state::Entity::delete_many()
        .filter(threat_source_state::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    threat_prefix::Entity::delete_many()
        .filter(threat_prefix::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    let now = chrono::Utc::now().naive_utc();
    firewall_rule::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        enabled: Set(true),
        priority: Set(10),
        action: Set("deny".to_string()),
        cidr: Set("203.0.113.0/24".to_string()),
        protocol: Set(None),
        port: Set(None),
        comment: Set(Some("example deny CIDR".to_string())),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    firewall_rule::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        enabled: Set(true),
        priority: Set(20),
        action: Set("allow".to_string()),
        cidr: Set("10.0.0.0/8".to_string()),
        protocol: Set(None),
        port: Set(None),
        comment: Set(Some("example private allow CIDR".to_string())),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    geo_country_policy::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        enabled: Set(true),
        country: Set("CN".to_string()),
        action: Set("allow".to_string()),
        packets_per_second: Set(None),
        burst: Set(None),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    ensure_default_dynamic_defense_exists(db, policy_name, now).await?;
    insert_builtin_threat_sources(db, policy_name).await?;
    let version = crate::db::next_policy_version(db, policy_name).await?;
    println!("seeded firewall policy at version {version}");
    Ok(())
}

fn default_dynamic_defense_active_model(
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> dynamic_defense::ActiveModel {
    let defaults = DynamicDefensePolicy::default();
    dynamic_defense::ActiveModel {
        policy_name: Set(policy_name.to_string()),
        enabled: Set(defaults.enabled),
        ip_rate_limit_enabled: Set(defaults.ip_rate_limit_enabled),
        ip_packets_per_second: Set(defaults.ip_packets_per_second.map(|value| value as i32)),
        ip_burst: Set(defaults.ip_burst.map(|value| value as i32)),
        flood_enabled: Set(defaults.flood_enabled),
        flood_packets_per_second: Set(defaults.flood_packets_per_second.map(|value| value as i32)),
        flood_burst: Set(defaults.flood_burst.map(|value| value as i32)),
        flood_block_seconds: Set(defaults.flood_block_seconds.map(|value| value as i32)),
        updated_at: Set(now),
    }
}

async fn insert_default_dynamic_defense(db: &DatabaseConnection, policy_name: &str) -> Result<()> {
    upsert_default_dynamic_defense(db, policy_name, chrono::Utc::now().naive_utc()).await
}

async fn ensure_default_dynamic_defense_exists(
    db: &DatabaseConnection,
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    if dynamic_defense::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .is_none()
    {
        default_dynamic_defense_active_model(policy_name, now)
            .insert(db)
            .await?;
    }
    Ok(())
}

async fn upsert_default_dynamic_defense(
    db: &DatabaseConnection,
    policy_name: &str,
    now: chrono::NaiveDateTime,
) -> Result<()> {
    dynamic_defense::Entity::insert(default_dynamic_defense_active_model(policy_name, now))
        .on_conflict(
            OnConflict::column(dynamic_defense::Column::PolicyName)
                .update_columns([
                    dynamic_defense::Column::Enabled,
                    dynamic_defense::Column::IpRateLimitEnabled,
                    dynamic_defense::Column::IpPacketsPerSecond,
                    dynamic_defense::Column::IpBurst,
                    dynamic_defense::Column::FloodEnabled,
                    dynamic_defense::Column::FloodPacketsPerSecond,
                    dynamic_defense::Column::FloodBurst,
                    dynamic_defense::Column::FloodBlockSeconds,
                    dynamic_defense::Column::UpdatedAt,
                ])
                .to_owned(),
        )
        .exec_without_returning(db)
        .await?;
    Ok(())
}

pub async fn show_policy(db: &DatabaseConnection, args: ShowPolicyArgs) -> Result<()> {
    let _ = args;
    let snapshot = load_policy(db, DEFAULT_POLICY_NAME).await?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

pub async fn ensure_configured_trusted_cidrs(
    db: &DatabaseConnection,
    policy: &str,
    values: &[String],
) -> Result<()> {
    let cidrs = normalize_trusted_cidrs(values)?;
    let explicitly_configured =
        !values.is_empty() || std::env::var_os("XDP_FIREWALL_TRUSTED_CIDRS").is_some();
    if cidrs.is_empty() && !explicitly_configured {
        return Ok(());
    }

    let now = chrono::Utc::now().naive_utc();
    let mut changed = 0_u64;
    let desired = cidrs.iter().cloned().collect::<HashSet<_>>();
    let existing_rows = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(policy))
        .all(db)
        .await?;

    for row in existing_rows {
        if desired.contains(&row.cidr) {
            if !row.enabled {
                let mut active: trusted_cidr::ActiveModel = row.into();
                active.enabled = Set(true);
                active.updated_at = Set(now);
                active.update(db).await?;
                changed += 1;
            }
        } else if row.enabled {
            let mut active: trusted_cidr::ActiveModel = row.into();
            active.enabled = Set(false);
            active.updated_at = Set(now);
            active.update(db).await?;
            changed += 1;
        }
    }

    for cidr in cidrs {
        if trusted_cidr::Entity::find()
            .filter(trusted_cidr::Column::PolicyName.eq(policy))
            .filter(trusted_cidr::Column::Cidr.eq(&cidr))
            .one(db)
            .await?
            .is_none()
        {
            trusted_cidr::ActiveModel {
                policy_name: Set(policy.to_string()),
                enabled: Set(true),
                cidr: Set(cidr),
                comment: Set(Some("initialized from API CLI/env".to_string())),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(db)
            .await?;
            changed += 1;
        }
    }

    if changed > 0 {
        let version = crate::db::next_policy_version(db, policy).await?;
        info!(
            policy,
            changed, version, "initialized trusted CIDRs from API CLI/env"
        );
    }
    Ok(())
}

fn normalize_trusted_cidrs(values: &[String]) -> Result<Vec<String>> {
    let mut cidrs = Vec::new();
    for value in values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let net = value
            .parse::<IpNet>()
            .with_context(|| format!("invalid trusted CIDR '{value}'"))?;
        let cidr = match net {
            IpNet::V4(net) => format!("{}/{}", net.network(), net.prefix_len()),
            IpNet::V6(net) => format!("{}/{}", net.network(), net.prefix_len()),
        };
        if !cidrs.contains(&cidr) {
            cidrs.push(cidr);
        }
    }
    Ok(cidrs)
}

fn parse_rule(row: firewall_rule::Model) -> Result<FirewallRule> {
    let port = row
        .port
        .map(|port| u16::try_from(port).context("firewall rule port is outside u16 range"))
        .transpose()?;
    Ok(FirewallRule {
        priority: row.priority,
        action: parse_action(&row.action)?,
        cidr: row
            .cidr
            .parse()
            .with_context(|| format!("invalid CIDR '{}'", row.cidr))?,
        protocol: row
            .protocol
            .as_deref()
            .map(parse_protocol)
            .transpose()?
            .unwrap_or(L4Protocol::Any),
        port,
        comment: row.comment,
    })
}

fn parse_geo_country_policy(row: geo_country_policy::Model) -> Result<GeoCountryPolicy> {
    Ok(GeoCountryPolicy {
        country: geo::normalize_country(&row.country)?,
        action: parse_action(&row.action)?,
    })
}

fn geo_prefix_to_ipnet(addr: IpAddr, prefix: u8) -> Result<IpNet> {
    IpNet::new(addr, prefix).with_context(|| format!("invalid geo prefix {addr}/{prefix}"))
}

fn parse_dynamic_defense(row: dynamic_defense::Model) -> Result<DynamicDefensePolicy> {
    Ok(DynamicDefensePolicy {
        enabled: row.enabled,
        ip_rate_limit_enabled: row.ip_rate_limit_enabled,
        ip_packets_per_second: row
            .ip_packets_per_second
            .map(|value| u32::try_from(value).context("dynamic defense ip pps is negative"))
            .transpose()?,
        ip_burst: row
            .ip_burst
            .map(|value| u32::try_from(value).context("dynamic defense ip burst is negative"))
            .transpose()?,
        flood_enabled: row.flood_enabled,
        flood_packets_per_second: row
            .flood_packets_per_second
            .map(|value| u32::try_from(value).context("dynamic defense flood pps is negative"))
            .transpose()?,
        flood_burst: row
            .flood_burst
            .map(|value| u32::try_from(value).context("dynamic defense flood burst is negative"))
            .transpose()?,
        flood_block_seconds: row
            .flood_block_seconds
            .map(|value| {
                u32::try_from(value).context("dynamic defense flood block seconds is negative")
            })
            .transpose()?,
    })
}

fn parse_dynamic_rate_limit(row: dynamic_rate_limit::Model) -> Result<DynamicRateLimitPolicy> {
    let port = row
        .port
        .map(|port| u16::try_from(port).context("dynamic rate limit port is outside u16 range"))
        .transpose()?;
    let policy = DynamicRateLimitPolicy {
        priority: row.priority,
        protocol: parse_protocol(&row.protocol)?,
        port,
        packets_per_second: u32::try_from(row.packets_per_second)
            .context("dynamic rate limit packets_per_second is negative")?,
        burst: u32::try_from(row.burst).context("dynamic rate limit burst is negative")?,
        comment: row.comment,
    };
    validate_dynamic_rate_limit_policy(&policy)?;
    Ok(policy)
}

fn parse_temp_ban(row: temp_ban::Model) -> Result<TempBanPolicy> {
    let port = row
        .port
        .map(|port| u16::try_from(port).context("temporary ban port is outside u16 range"))
        .transpose()?;
    let policy = TempBanPolicy {
        ip: row
            .ip
            .parse()
            .with_context(|| format!("invalid temporary ban IP '{}'", row.ip))?,
        protocol: parse_protocol(&row.protocol)?,
        port,
        expires_at: row.expires_at,
        comment: row.comment,
    };
    validate_temp_ban_policy(&policy)?;
    Ok(policy)
}

fn parse_trusted_cidr(row: trusted_cidr::Model) -> Result<TrustedCidrPolicy> {
    Ok(TrustedCidrPolicy {
        cidr: row
            .cidr
            .parse()
            .with_context(|| format!("invalid trusted CIDR '{}'", row.cidr))?,
        comment: row.comment,
    })
}

fn validate_dynamic_defense_policy(policy: &DynamicDefensePolicy) -> Result<()> {
    if !policy.enabled {
        return Ok(());
    }
    if policy.ip_rate_limit_enabled {
        require_positive_dynamic_value(
            "dynamic defense ip packets_per_second",
            policy.ip_packets_per_second,
        )?;
        require_positive_dynamic_value("dynamic defense ip burst", policy.ip_burst)?;
    }
    if policy.flood_enabled {
        require_positive_dynamic_value(
            "dynamic defense flood packets_per_second",
            policy.flood_packets_per_second,
        )?;
        require_positive_dynamic_value("dynamic defense flood burst", policy.flood_burst)?;
        require_positive_dynamic_value(
            "dynamic defense flood block seconds",
            policy.flood_block_seconds,
        )?;
    }
    Ok(())
}

fn validate_dynamic_rate_limit_policy(policy: &DynamicRateLimitPolicy) -> Result<()> {
    if policy.packets_per_second == 0 {
        bail!("dynamic rate limit packets_per_second must be greater than 0");
    }
    if policy.burst == 0 {
        bail!("dynamic rate limit burst must be greater than 0");
    }
    if matches!(policy.protocol, L4Protocol::Icmp) && policy.port.is_some() {
        bail!("dynamic rate limit icmp cannot set a port");
    }
    Ok(())
}

fn validate_temp_ban_policy(policy: &TempBanPolicy) -> Result<()> {
    if matches!(policy.protocol, L4Protocol::Icmp) && policy.port.is_some() {
        bail!("temporary ban icmp cannot set a port");
    }
    Ok(())
}

fn require_positive_dynamic_value(name: &str, value: Option<u32>) -> Result<()> {
    match value {
        Some(value) if value > 0 => Ok(()),
        Some(_) => bail!("{name} must be greater than 0 when dynamic defense is enabled"),
        None => bail!("{name} must be set when dynamic defense is enabled"),
    }
}

async fn insert_builtin_threat_sources(db: &DatabaseConnection, policy_name: &str) -> Result<u64> {
    let now = chrono::Utc::now().naive_utc();
    let existing_names = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .all(db)
        .await?
        .into_iter()
        .map(|source| source.name)
        .collect::<HashSet<_>>();
    let mut inserted = 0_u64;
    for source in threat::BUILTIN_THREAT_SOURCES {
        if existing_names.contains(source.name) {
            continue;
        }
        let model = threat_source::ActiveModel {
            policy_name: Set(policy_name.to_string()),
            enabled: Set(true),
            name: Set(source.name.to_string()),
            url: Set(source.url.to_string()),
            format: Set(source.format.to_string()),
            min_score: Set(source.min_score),
            updated_at: Set(now),
            ..Default::default()
        };
        threat_source::Entity::insert(model)
            .on_conflict(
                OnConflict::columns([
                    threat_source::Column::PolicyName,
                    threat_source::Column::Name,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(db)
            .await?;
        inserted += 1;
    }
    Ok(inserted)
}

fn parse_action(value: &str) -> Result<RuleAction> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok(RuleAction::Allow),
        "deny" | "drop" => Ok(RuleAction::Deny),
        _ => bail!("unsupported firewall action '{value}'"),
    }
}

fn parse_protocol(value: &str) -> Result<L4Protocol> {
    match value.to_ascii_lowercase().as_str() {
        "any" => Ok(L4Protocol::Any),
        "tcp" => Ok(L4Protocol::Tcp),
        "udp" => Ok(L4Protocol::Udp),
        "icmp" => Ok(L4Protocol::Icmp),
        _ => bail!("unsupported L4 protocol '{value}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::entities::geo_ip_prefix;
    use sea_orm::{ConnectOptions, Database};

    #[test]
    fn normalizes_trusted_cidrs_from_repeated_and_comma_values() {
        let cidrs = normalize_trusted_cidrs(&[
            "10.1.2.3/8".to_string(),
            "192.168.0.0/16,10.0.0.0/8".to_string(),
        ])
        .unwrap();

        assert_eq!(cidrs, vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    #[test]
    fn rejects_enabled_dynamic_defense_with_zero_values() {
        let policy = DynamicDefensePolicy {
            enabled: true,
            ip_rate_limit_enabled: true,
            ip_packets_per_second: Some(0),
            ip_burst: Some(DEFAULT_IP_RATE_LIMIT_BURST),
            flood_enabled: false,
            flood_packets_per_second: None,
            flood_burst: None,
            flood_block_seconds: None,
        };

        assert!(validate_dynamic_defense_policy(&policy).is_err());
    }

    #[test]
    fn rejects_enabled_dynamic_defense_with_missing_values() {
        let policy = DynamicDefensePolicy {
            enabled: true,
            ip_rate_limit_enabled: false,
            ip_packets_per_second: None,
            ip_burst: None,
            flood_enabled: true,
            flood_packets_per_second: Some(DEFAULT_FLOOD_PPS),
            flood_burst: None,
            flood_block_seconds: Some(DEFAULT_FLOOD_BLOCK_SECONDS),
        };

        assert!(validate_dynamic_defense_policy(&policy).is_err());
    }

    #[test]
    fn accepts_custom_dynamic_rate_limit_by_port_only() {
        let policy = DynamicRateLimitPolicy {
            priority: 10,
            protocol: L4Protocol::Any,
            port: Some(443),
            packets_per_second: 1_000,
            burst: 2_000,
            comment: None,
        };

        assert!(validate_dynamic_rate_limit_policy(&policy).is_ok());
    }

    #[tokio::test]
    async fn ensure_builtin_policy_adds_missing_builtin_sources_for_existing_policy() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        let now = chrono::Utc::now().naive_utc();

        policy_version::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            version: Set(7),
            updated_at: Set(now),
        }
        .insert(&db)
        .await
        .unwrap();

        for source in &threat::BUILTIN_THREAT_SOURCES[..2] {
            threat_source::ActiveModel {
                policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
                enabled: Set(true),
                name: Set(source.name.to_string()),
                url: Set(source.url.to_string()),
                format: Set(source.format.to_string()),
                min_score: Set(source.min_score),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(&db)
            .await
            .unwrap();
        }

        ensure_builtin_policy(&db, DEFAULT_POLICY_NAME)
            .await
            .unwrap();

        let sources = threat_source::Entity::find()
            .filter(threat_source::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
            .all(&db)
            .await
            .unwrap();
        assert_eq!(sources.len(), threat::BUILTIN_THREAT_SOURCES.len());
        assert!(sources.iter().any(|source| source.name == "voipbl"));

        let version = policy_version::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .version;
        assert_eq!(version, 8);

        ensure_builtin_policy(&db, DEFAULT_POLICY_NAME)
            .await
            .unwrap();
        let version = policy_version::Entity::find_by_id(DEFAULT_POLICY_NAME.to_string())
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .version;
        assert_eq!(version, 8);
    }

    #[test]
    fn rejects_custom_dynamic_rate_limit_icmp_port() {
        let policy = DynamicRateLimitPolicy {
            priority: 10,
            protocol: L4Protocol::Icmp,
            port: Some(443),
            packets_per_second: 1_000,
            burst: 2_000,
            comment: None,
        };

        assert!(validate_dynamic_rate_limit_policy(&policy).is_err());
    }

    #[tokio::test]
    async fn load_policy_without_geo_prefixes_keeps_country_rules_but_skips_prefixes() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        let now = chrono::Utc::now().naive_utc();

        geo_country_policy::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(true),
            country: Set("US".to_string()),
            action: Set("deny".to_string()),
            packets_per_second: Set(None),
            burst: Set(None),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        geo_ip_prefix::ActiveModel {
            country: Set("US".to_string()),
            cidrs_json: Set(r#"["203.0.113.0/24"]"#.to_string()),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let full = load_policy(&db, DEFAULT_POLICY_NAME).await.unwrap();
        assert_eq!(full.geo_countries.len(), 1);
        assert_eq!(full.geo_prefixes.len(), 1);

        let slim = load_policy_without_geo_prefixes(&db, DEFAULT_POLICY_NAME)
            .await
            .unwrap();
        assert_eq!(slim.geo_countries.len(), 1);
        assert!(slim.geo_prefixes.is_empty());
    }

    #[tokio::test]
    async fn load_policy_uses_persisted_threat_prefixes() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        let now = chrono::Utc::now().naive_utc();

        threat_source::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(true),
            name: Set("test-feed".to_string()),
            url: Set(
                "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt".to_string(),
            ),
            format: Set("ipsum".to_string()),
            min_score: Set(Some(3)),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        threat_prefix::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            source_name: Set("test-feed".to_string()),
            cidrs_json: Set(r#"["198.51.100.0/24","203.0.113.10/32"]"#.to_string()),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let snapshot = load_policy(&db, DEFAULT_POLICY_NAME).await.unwrap();
        assert_eq!(snapshot.threat_sources.len(), 1);
        assert_eq!(snapshot.threat_prefixes.len(), 2);

        let compiled = compile_policy(&snapshot).await.unwrap();
        assert_eq!(compiled.threat_prefixes.len(), 2);
        assert!(compiled.threat_prefixes.iter().all(|rule| {
            rule.action == RuleAction::Deny && rule.source == XdpRuleSource::ThreatIntel
        }));
    }
}
