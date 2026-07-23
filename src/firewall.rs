use crate::cli::{SeedExampleArgs, ShowPolicyArgs};
use crate::db::entities::{firewall_rule, geo_country_policy, policy_version, threat_source};
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
    pub packets_per_second: Option<u32>,
    pub burst: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub policy_name: String,
    pub version: i64,
    pub rules: Vec<FirewallRule>,
    pub geo_countries: Vec<GeoCountryPolicy>,
    pub threat_sources: Vec<threat::ThreatSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub version: i64,
    pub trusted_prefixes: Vec<XdpTrustedPrefix>,
    pub rules: Vec<XdpPrefixRule>,
    pub country_rules: Vec<XdpCountryRule>,
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
    pub packets_per_second: u32,
    pub burst: u32,
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

    Ok(PolicySnapshot {
        policy_name: policy_name.to_string(),
        version,
        rules,
        geo_countries,
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
                packets_per_second: policy.packets_per_second.unwrap_or(0),
                burst: policy.burst.unwrap_or(0),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CompiledPolicy {
        version: snapshot.version,
        trusted_prefixes: Vec::new(),
        rules,
        country_rules,
        geo_prefixes,
        threat_prefixes,
    })
}

pub async fn seed_example_policy(db: &DatabaseConnection, args: SeedExampleArgs) -> Result<()> {
    firewall_rule::Entity::delete_many()
        .filter(firewall_rule::Column::PolicyName.eq(&args.name))
        .exec(db)
        .await?;
    geo_country_policy::Entity::delete_many()
        .filter(geo_country_policy::Column::PolicyName.eq(&args.name))
        .exec(db)
        .await?;
    threat_source::Entity::delete_many()
        .filter(threat_source::Column::PolicyName.eq(&args.name))
        .exec(db)
        .await?;

    let now = chrono::Utc::now().naive_utc();
    firewall_rule::ActiveModel {
        policy_name: Set(args.name.clone()),
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
        policy_name: Set(args.name.clone()),
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
        policy_name: Set(args.name.clone()),
        enabled: Set(true),
        country: Set("CN".to_string()),
        action: Set("allow".to_string()),
        packets_per_second: Set(Some(10_000)),
        burst: Set(Some(20_000)),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await?;
    insert_builtin_threat_sources(db, &args.name).await?;
    let version = crate::db::next_policy_version(db, &args.name).await?;
    println!("seeded policy '{}' at version {}", args.name, version);
    Ok(())
}

pub async fn show_policy(db: &DatabaseConnection, args: ShowPolicyArgs) -> Result<()> {
    let snapshot = load_policy(db, &args.name).await?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
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
        packets_per_second: row
            .packets_per_second
            .map(|value| u32::try_from(value).context("geo packets_per_second is negative"))
            .transpose()?,
        burst: row
            .burst
            .map(|value| u32::try_from(value).context("geo burst is negative"))
            .transpose()?,
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
