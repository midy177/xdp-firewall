use crate::cli::{SeedExampleArgs, ShowPolicyArgs};
use crate::db::entities::{
    dynamic_defense, firewall_rule, geo_country_policy, policy_version, threat_source, trusted_cidr,
};
use crate::{geo, threat};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
    pub dynamic_defense: DynamicDefensePolicy,
    pub trusted_cidrs: Vec<TrustedCidrPolicy>,
    pub threat_sources: Vec<threat::ThreatSource>,
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
    pub dynamic_defense: XdpDynamicDefense,
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
    pub action: RuleAction,
    pub protocol: L4Protocol,
    pub port: u16,
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

pub async fn load_policy(db: &DatabaseConnection, policy_name: &str) -> Result<PolicySnapshot> {
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

    let threat_sources = threat_source::Entity::find()
        .filter(threat_source::Column::PolicyName.eq(policy_name))
        .filter(threat_source::Column::Enabled.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(threat::ThreatSource::try_from)
        .collect::<Result<Vec<_>>>()?;

    let dynamic_defense = dynamic_defense::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .map(parse_dynamic_defense)
        .transpose()?
        .unwrap_or_default();
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
        dynamic_defense,
        trusted_cidrs,
        threat_sources,
    })
}

pub async fn ensure_builtin_policy(db: &DatabaseConnection, policy_name: &str) -> Result<()> {
    if policy_version::Entity::find_by_id(policy_name.to_string())
        .one(db)
        .await?
        .is_some()
    {
        return Ok(());
    }

    insert_default_dynamic_defense(db, policy_name).await?;
    insert_builtin_threat_sources(db, policy_name).await?;
    let version = crate::db::next_policy_version(db, policy_name).await?;
    info!(
        policy = %policy_name,
        version,
        "initialized policy with built-in threat intelligence"
    );
    Ok(())
}

pub async fn compile_policy(snapshot: &PolicySnapshot) -> Result<CompiledPolicy> {
    let countries = snapshot
        .geo_countries
        .iter()
        .map(|policy| policy.country.clone())
        .collect::<Vec<_>>();
    let geo_prefixes = geo::fetch_ipdeny_prefixes(&countries)
        .await?
        .into_iter()
        .map(|prefix| XdpGeoPrefix {
            addr: prefix.addr,
            prefix: prefix.prefix,
            country: prefix.country,
        })
        .collect();
    let threat_prefixes = threat::fetch_threat_prefixes(&snapshot.threat_sources)
        .await?
        .into_iter()
        .map(|prefix| XdpPrefixRule {
            addr: prefix.addr,
            prefix: prefix.prefix,
            action: RuleAction::Deny,
            protocol: L4Protocol::Any,
            port: 0,
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
                action: rule.action,
                protocol: rule.protocol,
                port: rule.port.unwrap_or(0),
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

    Ok(CompiledPolicy {
        version: snapshot.version,
        trusted_prefixes,
        rules,
        country_rules,
        dynamic_defense,
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
    trusted_cidr::Entity::delete_many()
        .filter(trusted_cidr::Column::PolicyName.eq(policy_name))
        .exec(db)
        .await?;
    dynamic_defense::Entity::delete_by_id(policy_name.to_string())
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
    default_dynamic_defense_active_model(policy_name, now)
        .insert(db)
        .await?;
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
    default_dynamic_defense_active_model(policy_name, chrono::Utc::now().naive_utc())
        .insert(db)
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
    if cidrs.is_empty() {
        return Ok(());
    }

    let now = chrono::Utc::now().naive_utc();
    let mut changed = 0_u64;
    for cidr in cidrs {
        let existing = trusted_cidr::Entity::find()
            .filter(trusted_cidr::Column::PolicyName.eq(policy))
            .filter(trusted_cidr::Column::Cidr.eq(&cidr))
            .one(db)
            .await?;
        if let Some(row) = existing {
            if !row.enabled {
                let mut active: trusted_cidr::ActiveModel = row.into();
                active.enabled = Set(true);
                active.updated_at = Set(now);
                active.update(db).await?;
                changed += 1;
            }
        } else {
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

fn parse_trusted_cidr(row: trusted_cidr::Model) -> Result<TrustedCidrPolicy> {
    Ok(TrustedCidrPolicy {
        cidr: row
            .cidr
            .parse()
            .with_context(|| format!("invalid trusted CIDR '{}'", row.cidr))?,
        comment: row.comment,
    })
}

async fn insert_builtin_threat_sources(db: &DatabaseConnection, policy_name: &str) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    for source in threat::BUILTIN_THREAT_SOURCES {
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
    }
    Ok(())
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

    #[test]
    fn normalizes_trusted_cidrs_from_repeated_and_comma_values() {
        let cidrs = normalize_trusted_cidrs(&[
            "10.1.2.3/8".to_string(),
            "192.168.0.0/16,10.0.0.0/8".to_string(),
        ])
        .unwrap();

        assert_eq!(cidrs, vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }
}
