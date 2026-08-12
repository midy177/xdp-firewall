use crate::cli::{XdpReplaceArgs, XdpStatusArgs, XdpTempBansArgs, XdpUnloadArgs};
use crate::firewall::CompiledPolicy;
#[cfg(target_os = "linux")]
use crate::firewall::{
    L4Protocol, XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix, XdpRuleSource,
};
#[cfg(any(target_os = "linux", test))]
use crate::firewall::{RuleAction, XdpPrefixRule, XdpTempBan, XdpTrustedPrefix};
use anyhow::{Result, bail};
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DEFAULT_RULE_MAP_ENTRIES: u32 = 262_144;
pub const DEFAULT_GEO_MAP_ENTRIES: u32 = 262_144;
pub const DEFAULT_TRUSTED_MAP_ENTRIES: u32 = 4_096;
pub const DEFAULT_COUNTRY_MAP_ENTRIES: u32 = 676;
pub const DEFAULT_RATE_MAP_ENTRIES: u32 = 1_048_576;
pub const DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES: u32 = 4_096;
pub const DEFAULT_TEMP_BAN_MAP_ENTRIES: u32 = 4_096;
pub const STAT_PASS: u32 = 0;
pub const STAT_RULE_DROP: u32 = 1;
pub const STAT_GEO_DROP: u32 = 2;
pub const STAT_RATE_DROP: u32 = 3;
pub const STAT_FLOOD_DROP: u32 = 4;
pub const STAT_CUSTOM_RATE_DROP: u32 = 5;
pub const STAT_PARSE_DROP: u32 = 6;
pub const STAT_TEMP_BAN_DROP: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum XdpAttachMode {
    Auto,
    Driver,
    Skb,
}

impl XdpAttachMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Driver => "driver",
            Self::Skb => "skb",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum XdpAttachStrategy {
    Direct,
    Dispatcher,
}

impl XdpAttachStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Dispatcher => "dispatcher",
        }
    }
}

#[derive(Debug, Clone)]
pub struct XdpAttachOptions {
    pub mode: XdpAttachMode,
    pub strategy: XdpAttachStrategy,
    pub allow_replace: bool,
    pub auto_resize_maps: bool,
    pub run_priority: i32,
    pub loader_path: String,
    pub bpftool_path: String,
}

impl Default for XdpAttachOptions {
    fn default() -> Self {
        Self {
            mode: XdpAttachMode::Auto,
            strategy: XdpAttachStrategy::Direct,
            allow_replace: false,
            auto_resize_maps: true,
            run_priority: 10,
            loader_path: "xdp-loader".to_string(),
            bpftool_path: "bpftool".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpMapSizes {
    pub rule_entries: u32,
    pub geo_entries: u32,
    pub trusted_entries: u32,
    pub country_entries: u32,
    pub rate_entries: u32,
    pub custom_rate_limit_entries: u32,
    pub temp_ban_entries: u32,
}

impl Default for XdpMapSizes {
    fn default() -> Self {
        Self {
            rule_entries: DEFAULT_RULE_MAP_ENTRIES,
            geo_entries: DEFAULT_GEO_MAP_ENTRIES,
            trusted_entries: DEFAULT_TRUSTED_MAP_ENTRIES,
            country_entries: DEFAULT_COUNTRY_MAP_ENTRIES,
            rate_entries: DEFAULT_RATE_MAP_ENTRIES,
            custom_rate_limit_entries: DEFAULT_CUSTOM_RATE_LIMIT_MAP_ENTRIES,
            temp_ban_entries: DEFAULT_TEMP_BAN_MAP_ENTRIES,
        }
    }
}

impl XdpMapSizes {
    pub fn validate(self) -> Result<Self> {
        ensure_nonzero("rule_cidrs", self.rule_entries)?;
        ensure_nonzero("geo_cidrs", self.geo_entries)?;
        ensure_nonzero("trusted_cidrs", self.trusted_entries)?;
        ensure_nonzero("country_rules", self.country_entries)?;
        ensure_nonzero("rate_buckets", self.rate_entries)?;
        ensure_nonzero("custom_rate_limits", self.custom_rate_limit_entries)?;
        ensure_nonzero("temp_bans", self.temp_ban_entries)?;
        Ok(self)
    }
}

fn ensure_nonzero(map: &str, entries: u32) -> Result<()> {
    if entries == 0 {
        bail!("{map} capacity must be greater than 0");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const ACTION_ALLOW: u8 = 1;
#[cfg(target_os = "linux")]
const ACTION_DENY: u8 = 2;
#[cfg(target_os = "linux")]
const PROTO_ANY: u8 = 0;
#[cfg(target_os = "linux")]
const PROTO_ICMP: u8 = 1;
#[cfg(target_os = "linux")]
const PROTO_TCP: u8 = 6;
#[cfg(target_os = "linux")]
const PROTO_UDP: u8 = 17;
#[cfg(target_os = "linux")]
const RULE_SOURCE_FIREWALL: u8 = 1;
#[cfg(target_os = "linux")]
const RULE_SOURCE_THREAT: u8 = 2;

pub struct XdpManager {
    #[cfg(target_os = "linux")]
    inner: linux::LinuxXdpManager,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XdpStats {
    pub pass: u64,
    pub rule_drop: u64,
    pub geo_drop: u64,
    pub rate_drop: u64,
    pub flood_drop: u64,
    pub custom_rate_drop: u64,
    pub parse_drop: u64,
    pub temp_ban_drop: u64,
}

impl XdpStats {
    pub fn total_drop(self) -> u64 {
        self.rule_drop
            + self.geo_drop
            + self.rate_drop
            + self.flood_drop
            + self.custom_rate_drop
            + self.parse_drop
            + self.temp_ban_drop
    }
}

pub fn drop_events_pin_path(interface: &str) -> Result<std::path::PathBuf> {
    Ok(map_pin_dir(interface)?.join("drop_events"))
}

pub fn drop_config_pin_path(interface: &str) -> Result<std::path::PathBuf> {
    Ok(map_pin_dir(interface)?.join("drop_config"))
}

pub fn map_pin_dir(interface: &str) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from("/sys/fs/bpf/xdp-firewall")
        .join(sanitize_pin_component(interface)?))
}

pub fn existing_xdp_summary(interface: &str) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        return linux::existing_xdp_summary(interface);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        Ok(None)
    }
}

pub fn dispatcher_status(args: XdpStatusArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::dispatcher_status(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp status is only supported on Linux")
    }
}

pub fn dispatcher_temp_bans(args: XdpTempBansArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::dispatcher_temp_bans(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp temp-bans is only supported on Linux");
    }
}

pub fn dispatcher_unload(args: XdpUnloadArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::dispatcher_unload(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp unload is only supported on Linux")
    }
}

pub fn dispatcher_replace(args: XdpReplaceArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::dispatcher_replace(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("xdp replace is only supported on Linux")
    }
}

fn sanitize_pin_component(value: &str) -> Result<String> {
    let sanitized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        bail!("interface name '{value}' is not safe for bpffs pin path");
    }
    Ok(sanitized)
}

impl XdpManager {
    pub fn attach(
        interface: Option<&str>,
        object_path: &str,
        program_name: &str,
        map_sizes: XdpMapSizes,
        attach_options: XdpAttachOptions,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let map_sizes = map_sizes.validate()?;
            let interface = resolve_interface_name(interface)?;
            return Ok(Self {
                inner: linux::LinuxXdpManager::attach(
                    &interface,
                    object_path,
                    program_name,
                    map_sizes,
                    attach_options,
                )?,
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                interface,
                object_path,
                program_name,
                map_sizes,
                attach_options,
            );
            Ok(Self {})
        }
    }

    pub fn apply(&mut self, policy: &CompiledPolicy) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.apply(policy);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
            Ok(())
        }
    }

    pub fn interface_name(&self) -> &str {
        #[cfg(target_os = "linux")]
        {
            return self.inner.interface_name();
        }
        #[cfg(not(target_os = "linux"))]
        {
            "noop"
        }
    }

    pub fn interface_ips(&self) -> Vec<IpAddr> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.interface_ips();
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    pub fn stats(&self) -> Result<XdpStats> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.stats();
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(XdpStats::default())
        }
    }

    pub fn set_drop_monitor_enabled(&mut self, enabled: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.set_drop_monitor_enabled(enabled);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = enabled;
            Ok(())
        }
    }
}

pub fn resolve_interface_name(configured: Option<&str>) -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        return resolve_linux_interface_name(configured);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(configured
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("noop")
            .to_string())
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux_interface_name(configured: Option<&str>) -> Result<String> {
    use anyhow::{Context, bail};

    if let Some(interface) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(interface.to_string());
    }
    let routes = std::fs::read_to_string("/proc/net/route")
        .context("failed to read /proc/net/route for interface auto-detection")?;
    let mut candidates = routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() > 3 && fields[1] == "00000000").then(|| {
                let metric = fields
                    .get(6)
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(u32::MAX);
                (metric, fields[0].to_string())
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let Some((_, interface)) = candidates.into_iter().next() else {
        bail!("failed to auto-detect network interface from default route; pass --interface");
    };
    Ok(interface)
}

#[cfg(target_os = "linux")]
fn action_code(action: RuleAction) -> u8 {
    match action {
        RuleAction::Allow => ACTION_ALLOW,
        RuleAction::Deny => ACTION_DENY,
    }
}

#[cfg(target_os = "linux")]
fn rule_source_code(source: XdpRuleSource) -> u8 {
    match source {
        XdpRuleSource::FirewallRule => RULE_SOURCE_FIREWALL,
        XdpRuleSource::ThreatIntel => RULE_SOURCE_THREAT,
    }
}

#[cfg(target_os = "linux")]
fn rule_source_order(source: XdpRuleSource) -> u8 {
    match source {
        XdpRuleSource::ThreatIntel => 0,
        XdpRuleSource::FirewallRule => 1,
    }
}

#[cfg(target_os = "linux")]
fn proto_code(protocol: L4Protocol) -> u8 {
    match protocol {
        L4Protocol::Any => PROTO_ANY,
        L4Protocol::Tcp => PROTO_TCP,
        L4Protocol::Udp => PROTO_UDP,
        L4Protocol::Icmp => PROTO_ICMP,
    }
}

#[cfg(target_os = "linux")]
fn country_key(country: u16) -> u32 {
    u32::from(country)
}

#[cfg(any(target_os = "linux", test))]
fn validate_map_capacity(required: XdpMapSizes, configured: XdpMapSizes) -> Result<()> {
    ensure_capacity("rule_cidrs", required.rule_entries, configured.rule_entries)?;
    ensure_capacity(
        "trusted_cidrs",
        required.trusted_entries,
        configured.trusted_entries,
    )?;
    ensure_capacity("geo_cidrs", required.geo_entries, configured.geo_entries)?;
    ensure_capacity(
        "country_rules",
        required.country_entries,
        configured.country_entries,
    )?;
    ensure_capacity(
        "custom_rate_limits",
        required.custom_rate_limit_entries,
        configured.custom_rate_limit_entries,
    )?;
    ensure_capacity(
        "temp_bans",
        required.temp_ban_entries,
        configured.temp_ban_entries,
    )?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn resized_map_sizes(current: XdpMapSizes, required: XdpMapSizes) -> Result<Option<XdpMapSizes>> {
    let resized = XdpMapSizes {
        rule_entries: expanded_capacity("rule_cidrs", current.rule_entries, required.rule_entries)?,
        geo_entries: expanded_capacity("geo_cidrs", current.geo_entries, required.geo_entries)?,
        trusted_entries: expanded_capacity(
            "trusted_cidrs",
            current.trusted_entries,
            required.trusted_entries,
        )?,
        country_entries: expanded_capacity(
            "country_rules",
            current.country_entries,
            required.country_entries,
        )?,
        rate_entries: current.rate_entries,
        custom_rate_limit_entries: expanded_capacity(
            "custom_rate_limits",
            current.custom_rate_limit_entries,
            required.custom_rate_limit_entries,
        )?,
        temp_ban_entries: expanded_capacity(
            "temp_bans",
            current.temp_ban_entries,
            required.temp_ban_entries,
        )?,
    };
    Ok((resized != current).then_some(resized))
}

#[cfg(any(target_os = "linux", test))]
fn expanded_capacity(map: &str, current: u32, required: u32) -> Result<u32> {
    use anyhow::Context as _;

    if required <= current {
        return Ok(current);
    }
    let doubled = u64::from(current)
        .checked_mul(2)
        .with_context(|| format!("{map} capacity overflowed while resizing"))?;
    let target = doubled.max(u64::from(required)).max(1);
    let rounded = target
        .checked_next_power_of_two()
        .with_context(|| format!("{map} capacity overflowed while rounding resize target"))?;
    u32::try_from(rounded)
        .with_context(|| format!("{map} resized capacity {rounded} exceeds u32 max"))
}

#[cfg(any(target_os = "linux", test))]
fn compact_trusted_prefixes(prefixes: &[XdpTrustedPrefix]) -> Vec<XdpTrustedPrefix> {
    let mut compacted = Vec::with_capacity(prefixes.len());
    for (index, prefix) in prefixes.iter().enumerate() {
        if prefixes.iter().enumerate().any(|(other_index, other)| {
            other_index != index && trusted_prefix_covers(*other, *prefix)
        }) {
            continue;
        }
        compacted.push(*prefix);
    }
    compacted
}

#[cfg(any(target_os = "linux", test))]
fn trusted_prefix_covers(cover: XdpTrustedPrefix, prefix: XdpTrustedPrefix) -> bool {
    if cover == prefix || cover.prefix > prefix.prefix {
        return false;
    }
    let Some(cover) = trusted_prefix_ipnet(cover) else {
        return false;
    };
    let Some(prefix) = trusted_prefix_ipnet(prefix) else {
        return false;
    };
    match (cover, prefix) {
        (ipnet::IpNet::V4(cover), ipnet::IpNet::V4(prefix)) => cover.contains(&prefix.network()),
        (ipnet::IpNet::V6(cover), ipnet::IpNet::V6(prefix)) => cover.contains(&prefix.network()),
        _ => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn trusted_prefix_ipnet(prefix: XdpTrustedPrefix) -> Option<ipnet::IpNet> {
    ipnet::IpNet::new(prefix.addr, prefix.prefix)
        .ok()
        .map(|net| net.trunc())
}

#[cfg(any(target_os = "linux", test))]
fn compact_temp_bans(bans: &[XdpTempBan]) -> Vec<XdpTempBan> {
    let mut compacted = Vec::with_capacity(bans.len());
    for (index, ban) in bans.iter().enumerate() {
        if bans.iter().enumerate().any(|(other_index, other)| {
            other_index != index && temp_ban_covers_or_supersedes(*other, *ban)
        }) {
            continue;
        }
        compacted.push(*ban);
    }
    compacted
}

#[cfg(any(target_os = "linux", test))]
fn temp_ban_covers_or_supersedes(cover: XdpTempBan, ban: XdpTempBan) -> bool {
    if cover.protocol != ban.protocol || cover.port != ban.port {
        return false;
    }
    if cover.addr == ban.addr && cover.prefix == ban.prefix {
        return cover.expires_at > ban.expires_at;
    }
    if cover.prefix > ban.prefix || cover.expires_at < ban.expires_at {
        return false;
    }
    let Some(cover) = temp_ban_ipnet(cover) else {
        return false;
    };
    let Some(ban) = temp_ban_ipnet(ban) else {
        return false;
    };
    match (cover, ban) {
        (ipnet::IpNet::V4(cover), ipnet::IpNet::V4(ban)) => cover.contains(&ban.network()),
        (ipnet::IpNet::V6(cover), ipnet::IpNet::V6(ban)) => cover.contains(&ban.network()),
        _ => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn temp_ban_ipnet(ban: XdpTempBan) -> Option<ipnet::IpNet> {
    ipnet::IpNet::new(ban.addr, ban.prefix)
        .ok()
        .map(|net| net.trunc())
}

#[cfg(any(target_os = "linux", test))]
fn deny_rule_matching_local_cidr(
    rule: &XdpPrefixRule,
    local_cidrs: &[LocalInterfaceCidr],
) -> Option<LocalInterfaceCidr> {
    if rule.action != RuleAction::Deny {
        return None;
    }
    local_cidrs
        .iter()
        .copied()
        .find(|local| prefix_contains_ip(rule.addr, rule.prefix, local.ip))
}

#[cfg(any(target_os = "linux", test))]
fn temp_ban_matching_local_cidr(
    ban: XdpTempBan,
    local_cidrs: &[LocalInterfaceCidr],
) -> Option<LocalInterfaceCidr> {
    local_cidrs
        .iter()
        .copied()
        .find(|local| prefix_contains_ip(ban.addr, ban.prefix, local.ip))
}

#[cfg(any(target_os = "linux", test))]
fn prefix_contains_ip(addr: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    if addr.is_ipv4() != ip.is_ipv4() {
        return false;
    }
    ipnet::IpNet::new(addr, prefix)
        .ok()
        .map(|net| net.trunc().contains(&ip))
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", test))]
fn format_local_interface_cidrs(cidrs: &[LocalInterfaceCidr]) -> String {
    cidrs
        .iter()
        .map(|cidr| format!("{}/{}", cidr.ip, cidr.prefix))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalInterfaceCidr {
    ip: IpAddr,
    prefix: u8,
}

#[cfg(any(target_os = "linux", test))]
fn ensure_capacity(map: &str, needed: u32, configured: u32) -> Result<()> {
    if needed > configured {
        bail!("{map} needs {needed} entries but map capacity is {configured}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn usize_to_u32(map: &str, value: usize) -> Result<u32> {
    use anyhow::Context as _;

    u32::try_from(value).with_context(|| format!("{map} entry count {value} exceeds u32 max"))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{Context, bail};
    use aya::{
        Ebpf, EbpfLoader, Pod,
        maps::{
            Array as AyaArray, HashMap as AyaHashMap, IterableMap, LpmTrie, Map, MapData, MapType,
            PerCpuArray, PerfEventArray, lpm_trie::Key as LpmKey,
        },
        programs::{ProgramFd, ProgramInfo, Xdp, XdpMode},
    };
    use std::collections::HashSet;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use tracing::{debug, error, info, warn};

    pub struct LinuxXdpManager {
        interface: String,
        object_path: String,
        program_name: String,
        attach_options: XdpAttachOptions,
        _direct_netlink_link: Option<DirectNetlinkLink>,
        _ebpf: Ebpf,
        rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
        geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
        trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
        country_rules: AyaHashMap<MapData, u32, CountryValue>,
        defense_policy: AyaArray<MapData, DefenseValue>,
        custom_rate_limits: AyaHashMap<MapData, CustomRateKey, CustomRateValue>,
        temp_bans: LpmTrie<MapData, TempBanData, TempBanValue>,
        drop_config: AyaArray<MapData, DropConfigValue>,
        stats: PerCpuArray<MapData, u64>,
        _drop_events: PerfEventArray<MapData>,
        map_sizes: XdpMapSizes,
        local_interface_cidrs: Vec<LocalInterfaceCidr>,
    }

    struct DirectNetlinkLink {
        interface: String,
        if_index: i32,
        prog_fd: OwnedFd,
        mode: XdpAttachMode,
    }

    struct TemporaryBpffsPin {
        path: PathBuf,
    }

    impl Drop for TemporaryBpffsPin {
        fn drop(&mut self) {
            if let Err(err) = std::fs::remove_file(&self.path)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                warn!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to remove temporary bpffs pin"
                );
            }
        }
    }

    impl Drop for DirectNetlinkLink {
        fn drop(&mut self) {
            if let Err(err) =
                netlink_set_xdp_fd(self.if_index, None, Some(self.prog_fd.as_fd()), self.mode)
            {
                warn!(
                    interface = %self.interface,
                    mode = %self.mode.as_str(),
                    error = %err,
                    "failed to detach direct replacement XDP link"
                );
            }
        }
    }

    struct XdpMapBundle {
        rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
        geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
        trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
        country_rules: AyaHashMap<MapData, u32, CountryValue>,
        defense_policy: AyaArray<MapData, DefenseValue>,
        custom_rate_limits: AyaHashMap<MapData, CustomRateKey, CustomRateValue>,
        temp_bans: LpmTrie<MapData, TempBanData, TempBanValue>,
        drop_config: AyaArray<MapData, DropConfigValue>,
        stats: PerCpuArray<MapData, u64>,
        drop_events: PerfEventArray<MapData>,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct RuleData {
        family: u8,
        proto: u8,
        dport: u16,
        addr: [u8; 16],
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct GeoData {
        family: u8,
        pad: [u8; 3],
        addr: [u8; 16],
    }

    type RuleKey = LpmKey<RuleData>;
    type GeoKey = LpmKey<GeoData>;

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct TrustedData {
        family: u8,
        pad: [u8; 3],
        addr: [u8; 16],
    }

    type TrustedKey = LpmKey<TrustedData>;

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct RuleValue {
        action: u8,
        source: u8,
        pad: [u8; 2],
        priority: i32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct GeoValue {
        country: u16,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct CountryValue {
        action: u8,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct DefenseValue {
        enabled: u8,
        ip_rate_limit_enabled: u8,
        flood_enabled: u8,
        pad: u8,
        ip_packets_per_second: u32,
        ip_burst: u32,
        flood_packets_per_second: u32,
        flood_burst: u32,
        flood_block_ns: u64,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    struct CustomRateKey {
        proto: u8,
        pad: u8,
        dport: u16,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct CustomRateValue {
        packets_per_second: u32,
        burst: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct TempBanData {
        family: u8,
        proto: u8,
        dport: u16,
        addr: [u8; 16],
    }

    type TempBanKey = LpmKey<TempBanData>;

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct TempBanValue {
        expires_at_ns: u64,
    }

    #[derive(Debug, serde::Serialize)]
    struct PinnedTempBanEntry {
        cidr: String,
        protocol: String,
        port: String,
        expires_at_ns: u64,
        remaining_seconds: i64,
        active: bool,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct TrustedValue {
        value: u8,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct DropConfigValue {
        value: u8,
    }

    unsafe impl Pod for RuleData {}
    unsafe impl Pod for GeoData {}
    unsafe impl Pod for TrustedData {}
    unsafe impl Pod for RuleValue {}
    unsafe impl Pod for GeoValue {}
    unsafe impl Pod for CountryValue {}
    unsafe impl Pod for DefenseValue {}
    unsafe impl Pod for CustomRateKey {}
    unsafe impl Pod for CustomRateValue {}
    unsafe impl Pod for TempBanData {}
    unsafe impl Pod for TempBanValue {}
    unsafe impl Pod for TrustedValue {}
    unsafe impl Pod for DropConfigValue {}

    const DISPATCHER_REFERENCED_MAPS: &[&str] = &[
        "rule_cidrs",
        "geo_cidrs",
        "trusted_cidrs",
        "country_rules",
        "defense_policy",
        "rate_buckets",
        "custom_rate_limits",
        "temp_bans",
        "drop_config",
        "stats",
        "drop_events",
    ];

    pub(super) fn dispatcher_status(args: XdpStatusArgs) -> Result<()> {
        let interface = resolve_interface_name(args.interface.as_deref())?;
        if let Some(summary) = existing_xdp_summary(&interface)? {
            println!("interface={interface} xdp_attached=true summary={summary}");
        } else {
            println!("interface={interface} xdp_attached=false");
        }
        let output = run_xdp_loader_command(
            &args.xdp_loader_path,
            xdp_loader_verbose_args(args.verbose, ["status"]),
        )
        .with_context(|| format!("failed to run xdp-loader status for interface '{interface}'"))?;
        print_command_output(&output);
        ensure_success("xdp-loader status", &output)
    }

    pub(super) fn dispatcher_temp_bans(args: XdpTempBansArgs) -> Result<()> {
        let interface = resolve_interface_name(args.interface.as_deref())?;
        let entries = pinned_temp_bans(&interface)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&entries)?);
            return Ok(());
        }

        println!(
            "interface={} pinned_map={} temp_bans={}",
            interface,
            map_pin_dir(&interface)?.join("temp_bans").display(),
            entries.len()
        );
        if entries.is_empty() {
            return Ok(());
        }
        println!(
            "{:<45} {:<5} {:<6} {:<20} {:<17} active",
            "cidr", "proto", "port", "expires_at_ns", "remaining_seconds"
        );
        for entry in entries {
            println!(
                "{:<45} {:<5} {:<6} {:<20} {:<17} {}",
                entry.cidr,
                entry.protocol,
                entry.port,
                entry.expires_at_ns,
                entry.remaining_seconds,
                entry.active
            );
        }
        Ok(())
    }

    pub(super) fn dispatcher_unload(args: XdpUnloadArgs) -> Result<()> {
        let interface = require_explicit_interface(
            args.interface.as_deref(),
            "xdp unload requires --interface because it can detach dispatcher programs and remove bpffs pins",
        )?;
        dispatcher_unload_inner(
            &interface,
            &args.xdp_loader_path,
            args.id,
            args.all,
            args.remove_pins,
            args.clean,
            args.verbose,
            false,
        )
    }

    pub(super) fn dispatcher_replace(args: XdpReplaceArgs) -> Result<()> {
        let interface = require_explicit_interface(
            args.interface.as_deref(),
            "xdp replace requires --interface because it unloads dispatcher programs before loading the replacement",
        )?;
        if args.id.is_some() || args.all || args.remove_pins || args.clean {
            dispatcher_unload_inner(
                &interface,
                &args.xdp_loader_path,
                args.id,
                args.all,
                args.remove_pins,
                args.clean,
                args.verbose,
                true,
            )?;
        }
        let map_sizes = XdpMapSizes {
            rule_entries: args.rule_map_entries,
            geo_entries: args.geo_map_entries,
            trusted_entries: args.trusted_map_entries,
            country_entries: args.country_map_entries,
            rate_entries: args.rate_map_entries,
            custom_rate_limit_entries: args.custom_rate_limit_map_entries,
            temp_ban_entries: args.temp_ban_map_entries,
        };
        let _manager = LinuxXdpManager::attach(
            &interface,
            &args.xdp_object,
            &args.program,
            map_sizes,
            XdpAttachOptions {
                mode: args.xdp_mode,
                strategy: XdpAttachStrategy::Dispatcher,
                allow_replace: false,
                auto_resize_maps: true,
                run_priority: args.xdp_run_priority,
                loader_path: args.xdp_loader_path,
                bpftool_path: args.bpftool_path,
            },
        )?;
        println!(
            "dispatcher replacement loaded interface={} object={} program={} priority={} pins={}",
            interface,
            args.xdp_object,
            args.program,
            args.xdp_run_priority,
            map_pin_dir(&interface)?.display()
        );
        Ok(())
    }

    impl LinuxXdpManager {
        pub fn attach(
            interface: &str,
            object_path: &str,
            program_name: &str,
            map_sizes: XdpMapSizes,
            attach_options: XdpAttachOptions,
        ) -> Result<Self> {
            if !Path::new(object_path).exists() {
                bail!("XDP object '{}' does not exist", object_path);
            }
            let pin_dir = map_pin_dir(interface)?;
            let pin_dir_existed = pin_dir.exists();
            let mut dispatcher_loaded = false;
            let attach_result = (|| -> Result<Self> {
                prepare_map_pin_dir(&pin_dir)?;
                recreate_incompatible_pinned_maps(
                    interface,
                    program_name,
                    &attach_options,
                    &pin_dir,
                )?;
                let mut ebpf = load_object_with_pinned_maps(object_path, map_sizes, &pin_dir)?;
                let direct_netlink_link = match attach_options.strategy {
                    XdpAttachStrategy::Direct => {
                        if !attach_options.allow_replace {
                            ensure_no_existing_xdp(interface)?;
                        }
                        let program: &mut Xdp = ebpf
                            .program_mut(program_name)
                            .with_context(|| format!("XDP program '{program_name}' is missing"))?
                            .try_into()
                            .with_context(|| format!("program '{program_name}' is not XDP"))?;
                        program.load().context("failed to load XDP program")?;
                        attach_program(
                            program,
                            interface,
                            attach_options.mode,
                            attach_options.allow_replace,
                            &attach_options.bpftool_path,
                        )?
                    }
                    XdpAttachStrategy::Dispatcher => {
                        unload_dispatcher_programs_by_name(
                            &attach_options.loader_path,
                            interface,
                            program_name,
                            false,
                        )?;
                        run_xdp_loader_load(
                            interface,
                            object_path,
                            program_name,
                            &attach_options,
                            &pin_dir,
                        )?;
                        dispatcher_loaded = true;
                        verify_dispatcher_map_identity(
                            &attach_options.loader_path,
                            &attach_options.bpftool_path,
                            interface,
                            program_name,
                            &pin_dir,
                        )?;
                        None
                    }
                };
                let mut maps = take_maps(&mut ebpf)?;
                let actual_map_sizes = actual_map_sizes(&maps, map_sizes)?;
                let local_interface_cidrs = local_interface_cidrs(interface)?;
                let mut drop_config = maps.drop_config;
                set_drop_config(&mut drop_config, false)?;
                maps.drop_config = drop_config;
                info!(
                    interface,
                    strategy = %attach_options.strategy.as_str(),
                    pin_dir = %pin_dir.display(),
                    local_interface_cidrs = %format_local_interface_cidrs(&local_interface_cidrs),
                    local_interface_cidr_count = local_interface_cidrs.len(),
                    "XDP maps ready"
                );

                Ok(Self {
                    interface: interface.to_string(),
                    object_path: object_path.to_string(),
                    program_name: program_name.to_string(),
                    attach_options: attach_options.clone(),
                    _direct_netlink_link: direct_netlink_link,
                    _ebpf: ebpf,
                    rule_cidrs: maps.rule_cidrs,
                    geo_cidrs: maps.geo_cidrs,
                    trusted_cidrs: maps.trusted_cidrs,
                    country_rules: maps.country_rules,
                    defense_policy: maps.defense_policy,
                    custom_rate_limits: maps.custom_rate_limits,
                    temp_bans: maps.temp_bans,
                    drop_config: maps.drop_config,
                    stats: maps.stats,
                    _drop_events: maps.drop_events,
                    map_sizes: actual_map_sizes,
                    local_interface_cidrs,
                })
            })();
            if let Err(err) = attach_result {
                rollback_failed_attach(
                    interface,
                    program_name,
                    &attach_options,
                    &pin_dir,
                    pin_dir_existed,
                    dispatcher_loaded,
                );
                return Err(err);
            }
            attach_result
        }

        pub fn interface_name(&self) -> &str {
            &self.interface
        }

        pub fn interface_ips(&self) -> Vec<IpAddr> {
            self.local_interface_cidrs
                .iter()
                .map(|cidr| cidr.ip)
                .collect()
        }

        pub fn apply(&mut self, policy: &CompiledPolicy) -> Result<()> {
            let required = self.required_policy_map_sizes(policy)?;
            if let Some(resized) = resized_map_sizes(self.map_sizes, required)? {
                if !self.attach_options.auto_resize_maps {
                    validate_map_capacity(required, self.map_sizes)?;
                }
                self.resize_maps(resized, required)?;
            }
            self.apply_to_current_maps(policy)
        }

        fn apply_to_current_maps(&mut self, policy: &CompiledPolicy) -> Result<()> {
            let required = self.required_policy_map_sizes(policy)?;
            validate_map_capacity(required, self.map_sizes)?;
            let mut new_rule_ids = HashSet::new();
            let mut new_rules = Vec::new();
            let mut new_geo_ids = HashSet::new();
            let mut new_geo_prefixes = Vec::new();
            let mut new_trusted_ids = HashSet::new();
            let mut new_trusted_keys = Vec::new();
            let mut new_country_ids = HashSet::new();
            let mut new_country_rules = Vec::new();
            let mut new_custom_rate_ids = HashSet::new();
            let mut new_custom_rate_limits = Vec::new();
            let mut new_temp_ban_ids = HashSet::new();
            let mut new_temp_bans = Vec::new();

            self.put_dynamic_defense(&policy.dynamic_defense)?;
            let monotonic_now_ns = monotonic_now_ns()?;
            let wall_now = chrono::Utc::now().naive_utc();
            let temp_bans = compact_temp_bans(&policy.temp_bans);
            for ban in &temp_bans {
                if ban.expires_at <= wall_now {
                    continue;
                }
                if let Some(local) = temp_ban_matching_local_cidr(*ban, &self.local_interface_cidrs)
                {
                    error!(
                        interface = %self.interface,
                        local_ip = %local.ip,
                        local_prefix = local.prefix,
                        addr = %ban.addr,
                        prefix = ban.prefix,
                        protocol = ?ban.protocol,
                        port = ban.port,
                        "refusing to write temporary ban that matches the agent interface IP"
                    );
                    continue;
                }
                let key = temp_ban_key(ban.addr, ban.prefix, ban.protocol, ban.port);
                let id = temp_ban_key_id(&key);
                if new_temp_ban_ids.insert(id) {
                    new_temp_bans.push((key, ban));
                } else {
                    warn!(
                        addr = %ban.addr,
                        prefix = ban.prefix,
                        protocol = ?ban.protocol,
                        port = ban.port,
                        "skipping duplicate temporary ban key; first matching key remains active"
                    );
                }
            }
            for limit in &policy.dynamic_rate_limits {
                let key = custom_rate_key(limit.protocol, limit.port);
                let id = custom_rate_key_id(&key);
                if new_custom_rate_ids.insert(id) {
                    new_custom_rate_limits.push((key, limit));
                } else {
                    warn!(
                        protocol = ?limit.protocol,
                        port = limit.port,
                        "skipping duplicate custom dynamic rate-limit key; first matching key remains active"
                    );
                }
            }
            let trusted_prefixes = compact_trusted_prefixes(&policy.trusted_prefixes);
            for prefix in &trusted_prefixes {
                let key = trusted_key(prefix.addr, prefix.prefix);
                let id = trusted_key_id(&key);
                if new_trusted_ids.insert(id) {
                    new_trusted_keys.push(key);
                }
            }
            let mut ordered_rules = policy
                .threat_prefixes
                .iter()
                .chain(policy.rules.iter())
                .collect::<Vec<_>>();
            ordered_rules.sort_by(|left, right| {
                left.priority.cmp(&right.priority).then_with(|| {
                    rule_source_order(left.source).cmp(&rule_source_order(right.source))
                })
            });
            for rule in ordered_rules {
                if let Some(local) =
                    deny_rule_matching_local_cidr(rule, &self.local_interface_cidrs)
                {
                    error!(
                        interface = %self.interface,
                        local_ip = %local.ip,
                        local_prefix = local.prefix,
                        addr = %rule.addr,
                        prefix = rule.prefix,
                        protocol = ?rule.protocol,
                        port = rule.port,
                        source = ?rule.source,
                        "refusing to write XDP deny rule that matches the agent interface IP"
                    );
                    continue;
                }
                let key = rule_key(rule.addr, rule.prefix, rule.protocol, rule.port);
                let id = rule_key_id(&key);
                if new_rule_ids.insert(id) {
                    new_rules.push((key, rule));
                } else {
                    warn!(
                        addr = %rule.addr,
                        prefix = rule.prefix,
                        protocol = ?rule.protocol,
                        port = rule.port,
                        source = ?rule.source,
                        "skipping duplicate XDP rule key; first matching key remains active"
                    );
                }
            }
            for prefix in &policy.geo_prefixes {
                let key = geo_key(prefix.addr, prefix.prefix);
                let id = geo_key_id(&key);
                if new_geo_ids.insert(id) {
                    new_geo_prefixes.push((key, prefix));
                }
            }
            for country in &policy.country_rules {
                let key = country_key(country.country);
                if new_country_ids.insert(key) {
                    new_country_rules.push((key, country));
                }
            }
            for (key, ban) in &new_temp_bans {
                self.put_temp_ban_key(key, ban, wall_now, monotonic_now_ns)?;
            }
            for (key, limit) in &new_custom_rate_limits {
                self.put_custom_rate_key(key, limit)?;
            }
            for key in &new_trusted_keys {
                self.put_trusted_key(key)?;
            }
            for (key, rule) in &new_rules {
                self.put_rule_key(key, rule)?;
            }
            for (key, prefix) in &new_geo_prefixes {
                self.put_geo_key(key, prefix)?;
            }
            for (key, country) in &new_country_rules {
                self.put_country_key(*key, country)?;
            }
            self.remove_stale_policy_keys(
                &new_rule_ids,
                &new_geo_ids,
                &new_trusted_ids,
                &new_country_ids,
                &new_custom_rate_ids,
                &new_temp_ban_ids,
            )?;
            log_written_trusted_cidrs(&new_trusted_keys);
            Ok(())
        }

        pub fn stats(&self) -> Result<XdpStats> {
            Ok(XdpStats {
                pass: self.stat(STAT_PASS)?,
                rule_drop: self.stat(STAT_RULE_DROP)?,
                geo_drop: self.stat(STAT_GEO_DROP)?,
                rate_drop: self.stat(STAT_RATE_DROP)?,
                flood_drop: self.stat(STAT_FLOOD_DROP)?,
                custom_rate_drop: self.stat(STAT_CUSTOM_RATE_DROP)?,
                parse_drop: self.stat(STAT_PARSE_DROP)?,
                temp_ban_drop: self.stat(STAT_TEMP_BAN_DROP)?,
            })
        }

        fn stat(&self, index: u32) -> Result<u64> {
            let values = self
                .stats
                .get(&index, 0)
                .with_context(|| format!("failed to read XDP stats index {index}"))?;
            Ok(values.iter().copied().sum())
        }

        pub fn set_drop_monitor_enabled(&mut self, enabled: bool) -> Result<()> {
            set_drop_config(&mut self.drop_config, enabled)
        }

        fn put_dynamic_defense(&mut self, policy: &XdpDynamicDefense) -> Result<()> {
            self.defense_policy.set(
                0,
                DefenseValue {
                    enabled: u8::from(policy.enabled),
                    ip_rate_limit_enabled: u8::from(policy.ip_rate_limit_enabled),
                    flood_enabled: u8::from(policy.flood_enabled),
                    pad: 0,
                    ip_packets_per_second: policy.ip_packets_per_second,
                    ip_burst: policy.ip_burst,
                    flood_packets_per_second: policy.flood_packets_per_second,
                    flood_burst: policy.flood_burst,
                    flood_block_ns: u64::from(policy.flood_block_seconds) * 1_000_000_000,
                },
                0,
            )?;
            Ok(())
        }

        fn required_policy_map_sizes(&self, policy: &CompiledPolicy) -> Result<XdpMapSizes> {
            let rule_entries = policy
                .rules
                .len()
                .checked_add(policy.threat_prefixes.len())
                .context("rule entry count overflowed")?;
            let country_entries = policy
                .country_rules
                .iter()
                .map(|country| country.country)
                .collect::<HashSet<_>>()
                .len();

            Ok(XdpMapSizes {
                rule_entries: usize_to_u32("rule_cidrs", rule_entries)?,
                geo_entries: usize_to_u32("geo_cidrs", policy.geo_prefixes.len())?,
                trusted_entries: usize_to_u32(
                    "trusted_cidrs",
                    compact_trusted_prefixes(&policy.trusted_prefixes).len(),
                )?,
                country_entries: usize_to_u32("country_rules", country_entries)?,
                rate_entries: self.map_sizes.rate_entries,
                custom_rate_limit_entries: usize_to_u32(
                    "custom_rate_limits",
                    policy.dynamic_rate_limits.len(),
                )?,
                temp_ban_entries: usize_to_u32(
                    "temp_bans",
                    compact_temp_bans(&policy.temp_bans).len(),
                )?,
            })
        }

        fn resize_maps(&mut self, resized: XdpMapSizes, required: XdpMapSizes) -> Result<()> {
            warn!(
                interface = %self.interface,
                program = %self.program_name,
                old_rule_entries = self.map_sizes.rule_entries,
                new_rule_entries = resized.rule_entries,
                required_rule_entries = required.rule_entries,
                old_geo_entries = self.map_sizes.geo_entries,
                new_geo_entries = resized.geo_entries,
                required_geo_entries = required.geo_entries,
                old_trusted_entries = self.map_sizes.trusted_entries,
                new_trusted_entries = resized.trusted_entries,
                required_trusted_entries = required.trusted_entries,
                old_country_entries = self.map_sizes.country_entries,
                new_country_entries = resized.country_entries,
                required_country_entries = required.country_entries,
                old_custom_rate_limit_entries = self.map_sizes.custom_rate_limit_entries,
                new_custom_rate_limit_entries = resized.custom_rate_limit_entries,
                required_custom_rate_limit_entries = required.custom_rate_limit_entries,
                old_temp_ban_entries = self.map_sizes.temp_ban_entries,
                new_temp_ban_entries = resized.temp_ban_entries,
                required_temp_ban_entries = required.temp_ban_entries,
                "resizing XDP maps because policy exceeds current map capacity; XDP enforcement will be briefly reloaded"
            );
            self.detach_and_remove_pinned_maps_for_resize()?;
            let replacement = Self::attach(
                &self.interface,
                &self.object_path,
                &self.program_name,
                resized,
                self.attach_options.clone(),
            )?;
            *self = replacement;
            Ok(())
        }

        fn detach_and_remove_pinned_maps_for_resize(&mut self) -> Result<()> {
            match self.attach_options.strategy {
                XdpAttachStrategy::Direct => {
                    drop(self._direct_netlink_link.take());
                }
                XdpAttachStrategy::Dispatcher => {
                    unload_dispatcher_programs_by_name(
                        &self.attach_options.loader_path,
                        &self.interface,
                        &self.program_name,
                        true,
                    )?;
                }
            }
            remove_map_pin_dir(&self.interface)
        }

        fn put_trusted_key(&mut self, key: &TrustedKey) -> Result<()> {
            self.trusted_cidrs
                .insert(key, TrustedValue { value: 1 }, 0)?;
            Ok(())
        }

        fn put_rule_key(&mut self, key: &RuleKey, rule: &XdpPrefixRule) -> Result<()> {
            self.rule_cidrs.insert(
                key,
                RuleValue {
                    action: action_code(rule.action),
                    source: rule_source_code(rule.source),
                    pad: [0; 2],
                    priority: rule.priority,
                },
                0,
            )?;
            Ok(())
        }

        fn put_custom_rate_key(
            &mut self,
            key: &CustomRateKey,
            limit: &XdpDynamicRateLimit,
        ) -> Result<()> {
            self.custom_rate_limits.insert(
                key,
                CustomRateValue {
                    packets_per_second: limit.packets_per_second,
                    burst: limit.burst,
                },
                0,
            )?;
            Ok(())
        }

        fn put_temp_ban_key(
            &mut self,
            key: &TempBanKey,
            ban: &XdpTempBan,
            wall_now: chrono::NaiveDateTime,
            monotonic_now_ns: u64,
        ) -> Result<()> {
            let Some(remaining_ns) = ban
                .expires_at
                .signed_duration_since(wall_now)
                .num_nanoseconds()
            else {
                return Ok(());
            };
            if remaining_ns <= 0 {
                return Ok(());
            }
            let expires_at_ns = monotonic_now_ns
                .checked_add(remaining_ns as u64)
                .context("temporary ban monotonic expiration overflowed")?;
            self.temp_bans
                .insert(key, TempBanValue { expires_at_ns }, 0)?;
            Ok(())
        }

        fn put_geo_key(&mut self, key: &GeoKey, prefix: &XdpGeoPrefix) -> Result<()> {
            self.geo_cidrs.insert(
                key,
                GeoValue {
                    country: prefix.country,
                },
                0,
            )?;
            Ok(())
        }

        fn put_country_key(&mut self, key: u32, country: &XdpCountryRule) -> Result<()> {
            self.country_rules.insert(
                key,
                CountryValue {
                    action: action_code(country.action),
                },
                0,
            )?;
            Ok(())
        }

        fn remove_stale_policy_keys(
            &mut self,
            new_rule_ids: &HashSet<(u32, u8, u8, u16, [u8; 16])>,
            new_geo_ids: &HashSet<(u32, u8, [u8; 16])>,
            new_trusted_ids: &HashSet<(u32, u8, [u8; 16])>,
            new_country_ids: &HashSet<u32>,
            new_custom_rate_ids: &HashSet<(u8, u16)>,
            new_temp_ban_ids: &HashSet<(u32, u8, u8, u16, [u8; 16])>,
        ) -> Result<()> {
            let rule_keys = self
                .rule_cidrs
                .keys()
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to list rule_cidrs keys")?;
            for key in rule_keys {
                if !new_rule_ids.contains(&rule_key_id(&key)) {
                    self.rule_cidrs.remove(&key)?;
                }
            }
            let geo_keys = self
                .geo_cidrs
                .keys()
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to list geo_cidrs keys")?;
            for key in geo_keys {
                if !new_geo_ids.contains(&geo_key_id(&key)) {
                    self.geo_cidrs.remove(&key)?;
                }
            }
            let trusted_keys = self
                .trusted_cidrs
                .keys()
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to list trusted_cidrs keys")?;
            for key in trusted_keys {
                if !new_trusted_ids.contains(&trusted_key_id(&key)) {
                    self.trusted_cidrs.remove(&key)?;
                }
            }
            let country_keys = self
                .country_rules
                .keys()
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to list country_rules keys")?;
            for key in country_keys {
                if !new_country_ids.contains(&key) {
                    self.country_rules.remove(&key)?;
                }
            }
            let custom_rate_keys = self
                .custom_rate_limits
                .keys()
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to list custom_rate_limits keys")?;
            for key in custom_rate_keys {
                if !new_custom_rate_ids.contains(&custom_rate_key_id(&key)) {
                    self.custom_rate_limits.remove(&key)?;
                }
            }
            let temp_ban_keys = self
                .temp_bans
                .keys()
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to list temp_bans keys")?;
            for key in temp_ban_keys {
                if !new_temp_ban_ids.contains(&temp_ban_key_id(&key)) {
                    self.temp_bans.remove(&key)?;
                }
            }
            Ok(())
        }
    }

    fn set_drop_config(
        drop_config: &mut AyaArray<MapData, DropConfigValue>,
        enabled: bool,
    ) -> Result<()> {
        drop_config.set(
            0,
            DropConfigValue {
                value: u8::from(enabled),
            },
            0,
        )?;
        Ok(())
    }

    fn possible_cpu_map_entries() -> Result<u32> {
        let possible = std::fs::read_to_string("/sys/devices/system/cpu/possible")
            .context("failed to read /sys/devices/system/cpu/possible")?;
        let max_cpu = possible
            .trim()
            .split(',')
            .filter(|value| !value.trim().is_empty())
            .map(parse_cpu_range_end)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .context("possible CPU set is empty")?;
        u32::try_from(max_cpu + 1).context("possible CPU id is outside u32 range")
    }

    fn parse_cpu_range_end(value: &str) -> Result<usize> {
        let value = value.trim();
        let end = value
            .rsplit_once('-')
            .map_or(value, |(_, end)| end)
            .parse::<usize>()
            .with_context(|| format!("invalid CPU range '{value}'"))?;
        Ok(end)
    }

    fn prepare_map_pin_dir(pin_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(&pin_dir).with_context(|| {
            format!(
                "failed to create bpffs map pin directory '{}'",
                pin_dir.display()
            )
        })?;
        Ok(())
    }

    fn actual_map_sizes(maps: &XdpMapBundle, requested: XdpMapSizes) -> Result<XdpMapSizes> {
        Ok(XdpMapSizes {
            rule_entries: map_max_entries("rule_cidrs", maps.rule_cidrs.map())?,
            geo_entries: map_max_entries("geo_cidrs", maps.geo_cidrs.map())?,
            trusted_entries: map_max_entries("trusted_cidrs", maps.trusted_cidrs.map())?,
            country_entries: map_max_entries("country_rules", maps.country_rules.map())?,
            rate_entries: requested.rate_entries,
            custom_rate_limit_entries: map_max_entries(
                "custom_rate_limits",
                maps.custom_rate_limits.map(),
            )?,
            temp_ban_entries: map_max_entries("temp_bans", maps.temp_bans.map())?,
        })
    }

    fn recreate_incompatible_pinned_maps(
        interface: &str,
        program_name: &str,
        attach_options: &XdpAttachOptions,
        pin_dir: &Path,
    ) -> Result<()> {
        let Some(temp_bans_map_type) = pinned_map_type(pin_dir, "temp_bans")? else {
            return Ok(());
        };
        if temp_bans_map_type == MapType::LpmTrie {
            return Ok(());
        }

        match attach_options.strategy {
            XdpAttachStrategy::Direct if !attach_options.allow_replace => {
                ensure_no_existing_xdp(interface)?;
            }
            XdpAttachStrategy::Direct => {}
            XdpAttachStrategy::Dispatcher => {
                unload_dispatcher_programs_by_name(
                    &attach_options.loader_path,
                    interface,
                    program_name,
                    false,
                )?;
            }
        }

        warn!(
            interface,
            strategy = %attach_options.strategy.as_str(),
            pin_dir = %pin_dir.display(),
            old_temp_bans_map_type = ?temp_bans_map_type,
            "recreating pinned XDP maps because temp_bans map type changed"
        );
        std::fs::remove_dir_all(pin_dir).with_context(|| {
            format!(
                "failed to remove incompatible pinned map directory '{}'",
                pin_dir.display()
            )
        })?;
        std::fs::create_dir_all(pin_dir).with_context(|| {
            format!(
                "failed to recreate bpffs map pin directory '{}'",
                pin_dir.display()
            )
        })?;
        Ok(())
    }

    fn pinned_map_type(pin_dir: &Path, name: &str) -> Result<Option<MapType>> {
        let path = pin_dir.join(name);
        if !path.exists() {
            return Ok(None);
        }
        let map = MapData::from_pin(&path)
            .with_context(|| format!("failed to open pinned XDP map '{}'", path.display()))?;
        let info = map
            .info()
            .with_context(|| format!("failed to inspect pinned XDP map '{}'", path.display()))?;
        info.map_type()
            .with_context(|| format!("failed to read pinned XDP map type '{}'", path.display()))
            .map(Some)
    }

    fn local_interface_cidrs(interface: &str) -> Result<Vec<LocalInterfaceCidr>> {
        let output = std::process::Command::new("ip")
            .args(["-j", "addr", "show", "dev", interface])
            .output()
            .with_context(|| {
                format!("failed to inspect interface '{interface}' addresses with ip")
            })?;
        if !output.status.success() {
            bail!(
                "failed to inspect interface '{interface}' addresses: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let value = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .context("failed to parse ip JSON while detecting interface addresses")?;
        let mut cidrs = Vec::new();
        collect_interface_cidrs_from_json(&value, &mut cidrs);
        cidrs.sort_by(|left, right| {
            left.ip
                .cmp(&right.ip)
                .then_with(|| left.prefix.cmp(&right.prefix))
        });
        cidrs.dedup();
        Ok(cidrs)
    }

    fn collect_interface_cidrs_from_json(
        value: &serde_json::Value,
        cidrs: &mut Vec<LocalInterfaceCidr>,
    ) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(addr_info) = object.get("addr_info") {
                    collect_interface_cidrs_from_json(addr_info, cidrs);
                }
                if object
                    .get("family")
                    .and_then(|value| value.as_str())
                    .is_some_and(|family| matches!(family, "inet" | "inet6"))
                {
                    if let Some(local) = object.get("local").and_then(|value| value.as_str()) {
                        if let Ok(ip) = local.parse::<IpAddr>() {
                            let prefix = object
                                .get("prefixlen")
                                .and_then(|value| value.as_u64())
                                .and_then(|value| u8::try_from(value).ok())
                                .unwrap_or_else(|| if ip.is_ipv4() { 32 } else { 128 });
                            cidrs.push(LocalInterfaceCidr { ip, prefix });
                        }
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect_interface_cidrs_from_json(value, cidrs);
                }
            }
            _ => {}
        }
    }

    fn pinned_temp_bans(interface: &str) -> Result<Vec<PinnedTempBanEntry>> {
        let path = map_pin_dir(interface)?.join("temp_bans");
        let map = MapData::from_pin(&path)
            .with_context(|| format!("failed to open pinned temp_bans map '{}'", path.display()))?;
        let map_type = map
            .info()
            .context("failed to inspect pinned temp_bans map")?
            .map_type()
            .context("failed to read pinned temp_bans map type")?;
        if map_type != MapType::LpmTrie {
            bail!(
                "pinned temp_bans map has type {:?}; CIDR temporary bans require lpm_trie. Restart a CIDR-capable agent or unload with --remove-pins to recreate pinned maps.",
                map_type
            );
        }
        let temp_bans: LpmTrie<MapData, TempBanData, TempBanValue> =
            Map::LpmTrie(map)
                .try_into()
                .context("pinned temp_bans map has unexpected type")?;
        let now = monotonic_now_ns()?;
        let mut entries = temp_bans
            .iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list pinned temp_bans entries")?
            .into_iter()
            .map(|(key, value)| pinned_temp_ban_entry(key, value, now))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.cidr
                .cmp(&right.cidr)
                .then_with(|| left.protocol.cmp(&right.protocol))
                .then_with(|| left.port.cmp(&right.port))
        });
        Ok(entries)
    }

    fn pinned_temp_ban_entry(
        key: TempBanKey,
        value: TempBanValue,
        monotonic_now_ns: u64,
    ) -> PinnedTempBanEntry {
        let data = key.data();
        let prefix = key.prefix_len().saturating_sub(32);
        let addr = match data.family {
            4 => IpAddr::V4(Ipv4Addr::new(
                data.addr[0],
                data.addr[1],
                data.addr[2],
                data.addr[3],
            )),
            6 => IpAddr::V6(Ipv6Addr::from(data.addr)),
            _ => IpAddr::V6(Ipv6Addr::from(data.addr)),
        };
        let remaining_ns = i128::from(value.expires_at_ns) - i128::from(monotonic_now_ns);
        PinnedTempBanEntry {
            cidr: format!("{addr}/{prefix}"),
            protocol: protocol_name(data.proto).to_string(),
            port: match u16::from_be(data.dport) {
                0 => "*".to_string(),
                port => port.to_string(),
            },
            expires_at_ns: value.expires_at_ns,
            remaining_seconds: (remaining_ns / 1_000_000_000) as i64,
            active: value.expires_at_ns > monotonic_now_ns,
        }
    }

    fn protocol_name(protocol: u8) -> &'static str {
        match protocol {
            PROTO_ANY => "any",
            PROTO_TCP => "tcp",
            PROTO_UDP => "udp",
            PROTO_ICMP => "icmp",
            _ => "unknown",
        }
    }

    fn map_max_entries(name: &str, map: &MapData) -> Result<u32> {
        let info = map
            .info()
            .with_context(|| format!("failed to inspect XDP map '{name}'"))?;
        Ok(info.max_entries())
    }

    fn load_object_with_pinned_maps(
        object_path: &str,
        map_sizes: XdpMapSizes,
        pin_dir: &Path,
    ) -> Result<Ebpf> {
        let drop_event_entries = possible_cpu_map_entries()
            .context("failed to detect possible CPUs for drop_events map sizing")?;
        let mut loader = EbpfLoader::new();
        loader
            .default_map_pin_directory(pin_dir)
            .map_max_entries("rule_cidrs", map_sizes.rule_entries)
            .map_max_entries("geo_cidrs", map_sizes.geo_entries)
            .map_max_entries("trusted_cidrs", map_sizes.trusted_entries)
            .map_max_entries("country_rules", map_sizes.country_entries)
            .map_max_entries("rate_buckets", map_sizes.rate_entries)
            .map_max_entries("custom_rate_limits", map_sizes.custom_rate_limit_entries)
            .map_max_entries("temp_bans", map_sizes.temp_ban_entries)
            .map_max_entries("drop_events", drop_event_entries);
        loader
            .load_file(object_path)
            .with_context(|| format!("failed to load XDP object '{object_path}'"))
    }

    fn take_maps(ebpf: &mut Ebpf) -> Result<XdpMapBundle> {
        Ok(XdpMapBundle {
            rule_cidrs: ebpf
                .take_map("rule_cidrs")
                .context("missing XDP map 'rule_cidrs'")?
                .try_into()
                .context("XDP map 'rule_cidrs' has unexpected type")?,
            geo_cidrs: ebpf
                .take_map("geo_cidrs")
                .context("missing XDP map 'geo_cidrs'")?
                .try_into()
                .context("XDP map 'geo_cidrs' has unexpected type")?,
            trusted_cidrs: ebpf
                .take_map("trusted_cidrs")
                .context("missing XDP map 'trusted_cidrs'")?
                .try_into()
                .context("XDP map 'trusted_cidrs' has unexpected type")?,
            country_rules: ebpf
                .take_map("country_rules")
                .context("missing XDP map 'country_rules'")?
                .try_into()
                .context("XDP map 'country_rules' has unexpected type")?,
            defense_policy: ebpf
                .take_map("defense_policy")
                .context("missing XDP map 'defense_policy'")?
                .try_into()
                .context("XDP map 'defense_policy' has unexpected type")?,
            custom_rate_limits: ebpf
                .take_map("custom_rate_limits")
                .context("missing XDP map 'custom_rate_limits'")?
                .try_into()
                .context("XDP map 'custom_rate_limits' has unexpected type")?,
            temp_bans: ebpf
                .take_map("temp_bans")
                .context("missing XDP map 'temp_bans'")?
                .try_into()
                .context("XDP map 'temp_bans' has unexpected type")?,
            drop_config: ebpf
                .take_map("drop_config")
                .context("missing XDP map 'drop_config'")?
                .try_into()
                .context("XDP map 'drop_config' has unexpected type")?,
            stats: ebpf
                .take_map("stats")
                .context("missing XDP map 'stats'")?
                .try_into()
                .context("XDP map 'stats' has unexpected type")?,
            drop_events: ebpf
                .take_map("drop_events")
                .context("missing XDP map 'drop_events'")?
                .try_into()
                .context("XDP map 'drop_events' has unexpected type")?,
        })
    }

    fn attach_program(
        program: &mut Xdp,
        interface: &str,
        attach_mode: XdpAttachMode,
        allow_replace: bool,
        bpftool_path: &str,
    ) -> Result<Option<DirectNetlinkLink>> {
        match attach_mode {
            XdpAttachMode::Auto => {
                match attach_program_mode(
                    program,
                    interface,
                    XdpAttachMode::Driver,
                    allow_replace,
                    bpftool_path,
                ) {
                    Ok(link) => {
                        info!(interface, mode = "driver", "XDP program attached");
                        Ok(link)
                    }
                    Err(driver_err) => {
                        info!(
                            interface,
                            error = %driver_err,
                            "driver XDP attach unavailable; using skb mode"
                        );
                        let link = attach_program_mode(
                            program,
                            interface,
                            XdpAttachMode::Skb,
                            allow_replace,
                            bpftool_path,
                        )
                        .with_context(|| {
                            format!("driver XDP attach failed ({driver_err:#}); skb attach failed")
                        })?;
                        info!(interface, mode = "skb", "XDP program attached");
                        Ok(link)
                    }
                }
            }
            XdpAttachMode::Driver => {
                let link = attach_program_mode(
                    program,
                    interface,
                    XdpAttachMode::Driver,
                    allow_replace,
                    bpftool_path,
                )
                .context("failed to attach XDP program in driver mode")?;
                info!(interface, mode = "driver", "XDP program attached");
                Ok(link)
            }
            XdpAttachMode::Skb => {
                let link = attach_program_mode(
                    program,
                    interface,
                    XdpAttachMode::Skb,
                    allow_replace,
                    bpftool_path,
                )
                .context("failed to attach XDP program in skb mode")?;
                info!(interface, mode = "skb", "XDP program attached");
                Ok(link)
            }
        }
    }

    fn attach_program_mode(
        program: &mut Xdp,
        interface: &str,
        mode: XdpAttachMode,
        allow_replace: bool,
        bpftool_path: &str,
    ) -> Result<Option<DirectNetlinkLink>> {
        let Some(existing_id) = current_xdp_program_id(interface, mode)? else {
            program.attach(interface, xdp_mode(mode))?;
            return Ok(None);
        };
        if !allow_replace {
            bail!(
                "interface '{interface}' already has an XDP program id {existing_id} in {} mode",
                mode.as_str()
            );
        }
        let if_index = if_index(interface)?;
        let old_prog =
            program_fd_by_id(bpftool_path, interface, existing_id).with_context(|| {
                format!("failed to get fd for existing XDP program id {existing_id}")
            })?;
        let new_prog_fd = program
            .fd()
            .context("XDP program fd is not available after load")?
            .as_fd()
            .try_clone_to_owned()
            .context("failed to clone loaded XDP program fd for direct replacement tracking")?;
        netlink_set_xdp_fd(
            if_index,
            Some(new_prog_fd.as_fd()),
            Some(old_prog.as_fd()),
            mode,
        )
        .with_context(|| {
            format!(
                "failed to replace existing XDP program id {existing_id} on interface '{interface}' in {} mode",
                mode.as_str()
            )
        })?;
        info!(
            interface,
            mode = %mode.as_str(),
            replaced_program_id = existing_id,
            "replaced existing direct XDP program"
        );
        Ok(Some(DirectNetlinkLink {
            interface: interface.to_string(),
            if_index,
            prog_fd: new_prog_fd,
            mode,
        }))
    }

    fn xdp_mode(mode: XdpAttachMode) -> XdpMode {
        match mode {
            XdpAttachMode::Auto => XdpMode::Default,
            XdpAttachMode::Driver => XdpMode::Driver,
            XdpAttachMode::Skb => XdpMode::Skb,
        }
    }

    fn if_index(interface: &str) -> Result<i32> {
        let c_interface = std::ffi::CString::new(interface)
            .with_context(|| format!("interface '{interface}' contains an embedded NUL"))?;
        let index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if index == 0 {
            bail!("interface '{interface}' does not exist");
        }
        i32::try_from(index).context("interface index is outside i32 range")
    }

    fn program_fd_by_id(bpftool_path: &str, interface: &str, program_id: u32) -> Result<ProgramFd> {
        let safe_interface = sanitize_pin_component(interface)?;
        let pin_root = Path::new("/sys/fs/bpf/xdp-firewall");
        std::fs::create_dir_all(pin_root)
            .with_context(|| format!("failed to create bpffs pin root '{}'", pin_root.display()))?;
        let pin_path = pin_root.join(format!(
            ".direct-replace-old-{safe_interface}-{}-{program_id}",
            std::process::id()
        ));
        if pin_path.exists() {
            std::fs::remove_file(&pin_path).with_context(|| {
                format!(
                    "failed to remove stale temporary bpffs pin '{}'",
                    pin_path.display()
                )
            })?;
        }
        let output = std::process::Command::new(bpftool_path)
            .args(["prog", "pin", "id"])
            .arg(program_id.to_string())
            .arg(&pin_path)
            .output()
            .with_context(|| format!("failed to run '{bpftool_path} prog pin'"))?;
        if !output.status.success() {
            bail!(
                "bpftool failed to pin existing XDP program id {program_id}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let _pin = TemporaryBpffsPin {
            path: pin_path.clone(),
        };
        ProgramInfo::from_pin(&pin_path)
            .with_context(|| {
                format!(
                    "failed to open temporary bpffs pin '{}' for existing XDP program id {program_id}",
                    pin_path.display()
                )
            })?
            .fd()
            .context("failed to clone fd from temporary bpffs pin")
    }

    fn current_xdp_program_id(interface: &str, mode: XdpAttachMode) -> Result<Option<u32>> {
        let output = std::process::Command::new("ip")
            .args(["-j", "-details", "link", "show", "dev", interface])
            .output()
            .with_context(|| format!("failed to inspect interface '{interface}' with ip"))?;
        if !output.status.success() {
            bail!(
                "failed to inspect interface '{interface}' for XDP program id: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let value = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .context("failed to parse ip JSON while detecting current XDP program id")?;
        Ok(find_xdp_program_id(&value, mode))
    }

    fn find_xdp_program_id(value: &serde_json::Value, mode: XdpAttachMode) -> Option<u32> {
        let mut mode_specific = Vec::new();
        let mut generic = Vec::new();
        collect_xdp_program_ids(value, mode, &mut mode_specific, &mut generic);
        mode_specific
            .into_iter()
            .next()
            .or_else(|| (generic.len() == 1).then_some(generic[0]))
    }

    fn collect_xdp_program_ids(
        value: &serde_json::Value,
        mode: XdpAttachMode,
        mode_specific: &mut Vec<u32>,
        generic: &mut Vec<u32>,
    ) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    if let Some(id) = value.as_u64().and_then(|id| u32::try_from(id).ok()) {
                        match key.as_str() {
                            "drv_prog_id" if mode == XdpAttachMode::Driver => {
                                mode_specific.push(id)
                            }
                            "skb_prog_id" if mode == XdpAttachMode::Skb => mode_specific.push(id),
                            "prog_id" => generic.push(id),
                            _ => {}
                        }
                    }
                }
                let mode_hint = object
                    .get("mode")
                    .or_else(|| object.get("attached"))
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if let Some(id) = object
                    .get("prog_id")
                    .and_then(|value| value.as_u64())
                    .and_then(|id| u32::try_from(id).ok())
                {
                    let matches_mode = match mode {
                        XdpAttachMode::Driver => {
                            mode_hint.contains("drv")
                                || mode_hint.contains("driver")
                                || mode_hint.contains("native")
                        }
                        XdpAttachMode::Skb => {
                            mode_hint.contains("skb") || mode_hint.contains("generic")
                        }
                        XdpAttachMode::Auto => false,
                    };
                    if matches_mode {
                        mode_specific.push(id);
                    }
                }
                for value in object.values() {
                    collect_xdp_program_ids(value, mode, mode_specific, generic);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect_xdp_program_ids(value, mode, mode_specific, generic);
                }
            }
            _ => {}
        }
    }

    fn netlink_set_xdp_fd(
        if_index: i32,
        fd: Option<BorrowedFd<'_>>,
        expected_fd: Option<BorrowedFd<'_>>,
        mode: XdpAttachMode,
    ) -> Result<()> {
        const NLM_F_REQUEST: u16 = 1;
        const NLM_F_ACK: u16 = 4;
        const NLMSG_ERROR: u16 = 2;
        const RTM_SETLINK: u16 = 19;
        const IFLA_XDP: u16 = 43;
        const NLA_F_NESTED: u16 = 1 << 15;
        const IFLA_XDP_FD: u16 = 1;
        const IFLA_XDP_FLAGS: u16 = 3;
        const IFLA_XDP_EXPECTED_FD: u16 = 8;
        const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
        const XDP_FLAGS_SKB_MODE: u32 = 2;
        const XDP_FLAGS_DRV_MODE: u32 = 4;
        const XDP_FLAGS_REPLACE: u32 = 16;

        let mode_flags = match mode {
            XdpAttachMode::Driver => XDP_FLAGS_DRV_MODE,
            XdpAttachMode::Skb => XDP_FLAGS_SKB_MODE,
            XdpAttachMode::Auto => 0,
        };
        let mut flags = mode_flags | XDP_FLAGS_UPDATE_IF_NOEXIST;
        if expected_fd.is_some() {
            flags |= XDP_FLAGS_REPLACE;
        }

        let mut xdp_attrs = Vec::new();
        push_attr_i32(
            &mut xdp_attrs,
            IFLA_XDP_FD,
            fd.map_or(-1, |fd| fd.as_raw_fd()),
        );
        push_attr_u32(&mut xdp_attrs, IFLA_XDP_FLAGS, flags);
        if let Some(expected_fd) = expected_fd {
            push_attr_i32(
                &mut xdp_attrs,
                IFLA_XDP_EXPECTED_FD,
                expected_fd.as_raw_fd(),
            );
        }

        let mut payload = Vec::new();
        let mut if_info = unsafe { std::mem::zeroed::<libc::ifinfomsg>() };
        if_info.ifi_family = libc::AF_UNSPEC as u8;
        if_info.ifi_index = if_index;
        push_pod(&mut payload, &if_info);
        push_attr_bytes(&mut payload, IFLA_XDP | NLA_F_NESTED, &xdp_attrs);

        let header_len = std::mem::size_of::<libc::nlmsghdr>();
        let mut message = Vec::with_capacity(header_len + payload.len());
        let header = libc::nlmsghdr {
            nlmsg_len: u32::try_from(header_len + payload.len())
                .context("netlink XDP message is too large")?,
            nlmsg_type: RTM_SETLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        push_pod(&mut message, &header);
        message.extend_from_slice(&payload);

        let socket = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to open netlink socket");
        }
        let socket = OwnedFd::from_raw_fd_checked(socket)?;
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to send netlink XDP replace request");
        }

        let mut buffer = [0_u8; 8192];
        loop {
            let len = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if len < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to receive netlink XDP replace ack");
            }
            let len = len as usize;
            let mut offset = 0;
            while offset + header_len <= len {
                let header = read_unaligned::<libc::nlmsghdr>(&buffer[offset..])?;
                if header.nlmsg_len == 0 {
                    bail!("received invalid zero-length netlink message");
                }
                let message_len = nla_align(header.nlmsg_len as usize);
                if offset + message_len > len {
                    bail!("received truncated netlink message");
                }
                if header.nlmsg_type == NLMSG_ERROR {
                    let error_offset = offset + header_len;
                    let error = read_unaligned::<i32>(&buffer[error_offset..])?;
                    if error == 0 {
                        return Ok(());
                    }
                    return Err(std::io::Error::from_raw_os_error(-error))
                        .context("netlink rejected XDP replace request");
                }
                offset += message_len;
            }
        }
    }

    trait OwnedFdExt {
        fn from_raw_fd_checked(fd: i32) -> Result<OwnedFd>;
    }

    impl OwnedFdExt for OwnedFd {
        fn from_raw_fd_checked(fd: i32) -> Result<OwnedFd> {
            use std::os::fd::FromRawFd;
            if fd < 0 {
                bail!("invalid raw fd {fd}");
            }
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RtAttr {
        rta_len: u16,
        rta_type: u16,
    }

    fn push_attr_i32(buffer: &mut Vec<u8>, attr_type: u16, value: i32) {
        push_attr_bytes(buffer, attr_type, &value.to_ne_bytes());
    }

    fn push_attr_u32(buffer: &mut Vec<u8>, attr_type: u16, value: u32) {
        push_attr_bytes(buffer, attr_type, &value.to_ne_bytes());
    }

    fn push_attr_bytes(buffer: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        let attr_len = std::mem::size_of::<RtAttr>() + value.len();
        let attr = RtAttr {
            rta_len: attr_len as u16,
            rta_type: attr_type,
        };
        push_pod(buffer, &attr);
        buffer.extend_from_slice(value);
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
    }

    fn push_pod<T>(buffer: &mut Vec<u8>, value: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(value).cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        };
        buffer.extend_from_slice(bytes);
    }

    fn read_unaligned<T: Copy>(buffer: &[u8]) -> Result<T> {
        if buffer.len() < std::mem::size_of::<T>() {
            bail!("buffer too small for netlink value");
        }
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<T>()) })
    }

    fn nla_align(value: usize) -> usize {
        const NLA_ALIGNTO: usize = 4;
        (value + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
    }

    fn run_xdp_loader_load(
        interface: &str,
        object_path: &str,
        program_name: &str,
        options: &XdpAttachOptions,
        pin_dir: &Path,
    ) -> Result<()> {
        match options.mode {
            XdpAttachMode::Auto => {
                if let Err(driver_err) = run_xdp_loader_load_mode(
                    interface,
                    object_path,
                    program_name,
                    options,
                    pin_dir,
                    "native",
                ) {
                    info!(
                        interface,
                        error = %driver_err,
                        "dispatcher native XDP attach unavailable; using skb mode"
                    );
                    run_xdp_loader_load_mode(
                        interface,
                        object_path,
                        program_name,
                        options,
                        pin_dir,
                        "skb",
                    )
                    .with_context(|| {
                        format!(
                            "dispatcher native XDP attach failed ({driver_err:#}); skb attach failed"
                        )
                    })?;
                    info!(interface, mode = "skb", "XDP dispatcher program attached");
                } else {
                    info!(
                        interface,
                        mode = "native",
                        "XDP dispatcher program attached"
                    );
                }
            }
            XdpAttachMode::Driver => {
                run_xdp_loader_load_mode(
                    interface,
                    object_path,
                    program_name,
                    options,
                    pin_dir,
                    "native",
                )?;
                info!(
                    interface,
                    mode = "native",
                    "XDP dispatcher program attached"
                );
            }
            XdpAttachMode::Skb => {
                run_xdp_loader_load_mode(
                    interface,
                    object_path,
                    program_name,
                    options,
                    pin_dir,
                    "skb",
                )?;
                info!(interface, mode = "skb", "XDP dispatcher program attached");
            }
        }
        Ok(())
    }

    fn run_xdp_loader_load_mode(
        interface: &str,
        object_path: &str,
        program_name: &str,
        options: &XdpAttachOptions,
        pin_dir: &Path,
        mode: &str,
    ) -> Result<()> {
        let pin_dir = pin_dir
            .to_str()
            .context("XDP map pin directory is not valid UTF-8")?;
        let priority = options.run_priority.to_string();
        let output = std::process::Command::new(&options.loader_path)
            .args([
                "load",
                "--mode",
                mode,
                "--pin-path",
                pin_dir,
                "--prog-name",
                program_name,
                "--prio",
                &priority,
                interface,
                object_path,
            ])
            .output()
            .with_context(|| {
                format!(
                    "failed to execute xdp-loader '{}' for dispatcher attach",
                    options.loader_path
                )
            })?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "xdp-loader dispatcher attach failed in {mode} mode: status={} stdout='{}' stderr='{}'",
                output.status,
                stdout.trim(),
                stderr.trim()
            );
        }
        Ok(())
    }

    fn dispatcher_unload_inner(
        interface: &str,
        loader_path: &str,
        program_id: Option<u32>,
        all: bool,
        remove_pins: bool,
        clean: bool,
        verbose: u8,
        tolerate_missing: bool,
    ) -> Result<()> {
        if !all && program_id.is_none() {
            bail!("xdp unload/replace requires either --all or --id <program-id>");
        }
        if remove_pins && !all {
            bail!(
                "--remove-pins requires --all so pinned maps are not removed while another dispatcher program may still use them"
            );
        }
        let mut args = xdp_loader_verbose_args(verbose, ["unload"]);
        if all {
            args.push("--all".to_string());
        } else if let Some(id) = program_id {
            args.push("--id".to_string());
            args.push(id.to_string());
        }
        args.push(interface.to_string());
        let output = run_xdp_loader_command(loader_path, args)
            .with_context(|| format!("failed to run xdp-loader unload for '{interface}'"))?;
        print_command_output(&output);
        if let Err(err) = ensure_success("xdp-loader unload", &output) {
            if tolerate_missing && is_no_dispatcher_output(&output) {
                debug!(
                    interface,
                    error = %err,
                    "dispatcher unload found no matching program; continuing"
                );
            } else {
                return Err(err);
            }
        }

        if clean {
            let mut clean_args = xdp_loader_verbose_args(verbose, ["clean"]);
            clean_args.push(interface.to_string());
            let clean_output = run_xdp_loader_command(loader_path, clean_args)
                .with_context(|| format!("failed to run xdp-loader clean for '{interface}'"))?;
            print_command_output(&clean_output);
            ensure_success("xdp-loader clean", &clean_output)?;
        }

        if remove_pins {
            remove_map_pin_dir(&interface)?;
        }
        println!("dispatcher unload completed interface={interface}");
        Ok(())
    }

    fn remove_map_pin_dir(interface: &str) -> Result<()> {
        let pin_dir = map_pin_dir(interface)?;
        match std::fs::remove_dir_all(&pin_dir) {
            Ok(()) => {
                println!("removed pinned map directory {}", pin_dir.display());
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| {
                format!(
                    "failed to remove pinned map directory '{}'",
                    pin_dir.display()
                )
            }),
        }
    }

    fn require_explicit_interface(configured: Option<&str>, message: &str) -> Result<String> {
        let Some(interface) = configured.map(str::trim).filter(|value| !value.is_empty()) else {
            bail!("{message}");
        };
        resolve_interface_name(Some(interface))
    }

    fn rollback_failed_attach(
        interface: &str,
        program_name: &str,
        attach_options: &XdpAttachOptions,
        pin_dir: &Path,
        pin_dir_existed: bool,
        dispatcher_loaded: bool,
    ) {
        if dispatcher_loaded {
            if let Err(err) = unload_dispatcher_programs_by_name(
                &attach_options.loader_path,
                interface,
                program_name,
                true,
            ) {
                warn!(
                    interface,
                    program = program_name,
                    error = %err,
                    "failed to roll back dispatcher program after attach failure"
                );
            }
        }
        if !pin_dir_existed {
            match std::fs::remove_dir_all(pin_dir) {
                Ok(()) => {
                    debug!(pin_dir = %pin_dir.display(), "removed pin directory after attach failure");
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    warn!(
                        pin_dir = %pin_dir.display(),
                        error = %err,
                        "failed to remove pin directory after attach failure"
                    );
                }
            }
        }
    }

    fn unload_dispatcher_programs_by_name(
        loader_path: &str,
        interface: &str,
        program_name: &str,
        tolerate_missing: bool,
    ) -> Result<()> {
        let ids = dispatcher_program_ids_by_name(loader_path, interface, program_name)?;
        if ids.is_empty() {
            return Ok(());
        }
        info!(
            interface,
            program = program_name,
            count = ids.len(),
            "unloading existing dispatcher program before attach"
        );
        for id in ids {
            let output = run_xdp_loader_command(
                loader_path,
                vec![
                    "unload".to_string(),
                    "--id".to_string(),
                    id.to_string(),
                    interface.to_string(),
                ],
            )
            .with_context(|| {
                format!("failed to run xdp-loader unload --id {id} for '{interface}'")
            })?;
            print_command_output(&output);
            if let Err(err) = ensure_success("xdp-loader unload --id", &output) {
                if tolerate_missing && is_no_dispatcher_output(&output) {
                    debug!(
                        interface,
                        program = program_name,
                        id,
                        error = %err,
                        "dispatcher program was already gone during cleanup"
                    );
                } else {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    fn dispatcher_program_ids_by_name(
        loader_path: &str,
        interface: &str,
        program_name: &str,
    ) -> Result<Vec<u32>> {
        let output = run_xdp_loader_command(loader_path, vec!["status".to_string()])
            .with_context(|| "failed to run xdp-loader status before dispatcher attach")?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "xdp-loader status failed before dispatcher attach: status={} stdout='{}' stderr='{}'",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_dispatcher_program_ids(&stdout, interface, program_name)
    }

    fn verify_dispatcher_map_identity(
        loader_path: &str,
        bpftool_path: &str,
        interface: &str,
        program_name: &str,
        pin_dir: &Path,
    ) -> Result<()> {
        let ids = dispatcher_program_ids_by_name(loader_path, interface, program_name)?;
        let [program_id] = ids.as_slice() else {
            bail!(
                "expected exactly one dispatcher program named '{program_name}' on interface '{interface}' after attach, found {}",
                ids.len()
            );
        };
        let program_map_ids = bpftool_program_map_ids(bpftool_path, *program_id)?;
        let expected = pinned_map_ids(pin_dir)?;
        let missing = expected
            .iter()
            .filter(|(_, map_id)| !program_map_ids.contains(map_id))
            .map(|(name, map_id)| format!("{name}:{map_id}"))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!(
                "dispatcher program id {program_id} is not using pinned XDP maps from '{}'; missing map ids: {}",
                pin_dir.display(),
                missing.join(", ")
            );
        }
        info!(
            interface,
            program = program_name,
            program_id,
            maps = expected.len(),
            "verified dispatcher program uses pinned XDP maps"
        );
        Ok(())
    }

    fn pinned_map_ids(pin_dir: &Path) -> Result<Vec<(&'static str, u32)>> {
        DISPATCHER_REFERENCED_MAPS
            .iter()
            .map(|name| {
                let path = pin_dir.join(name);
                let map = MapData::from_pin(&path).with_context(|| {
                    format!("failed to open pinned XDP map '{}'", path.display())
                })?;
                let id = map
                    .info()
                    .with_context(|| {
                        format!("failed to inspect pinned XDP map '{}'", path.display())
                    })?
                    .id();
                Ok((*name, id))
            })
            .collect()
    }

    fn bpftool_program_map_ids(bpftool_path: &str, program_id: u32) -> Result<HashSet<u32>> {
        let program_id_arg = program_id.to_string();
        let output = std::process::Command::new(bpftool_path)
            .args(["-j", "prog", "show", "id", &program_id_arg])
            .output()
            .with_context(|| {
                format!(
                    "failed to execute bpftool '{bpftool_path}' for dispatcher map verification"
                )
            })?;
        if !output.status.success() {
            bail!(
                "bpftool prog show id {program_id} failed: status={} stdout='{}' stderr='{}'",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let value = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .context("failed to parse bpftool JSON while verifying dispatcher maps")?;
        let mut ids = HashSet::new();
        collect_map_ids_from_json(&value, &mut ids);
        if ids.is_empty() {
            bail!("bpftool did not report any map_ids for dispatcher program id {program_id}");
        }
        Ok(ids)
    }

    fn collect_map_ids_from_json(value: &serde_json::Value, ids: &mut HashSet<u32>) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(map_ids) = object.get("map_ids").and_then(|value| value.as_array()) {
                    for id in map_ids {
                        if let Some(id) = id.as_u64().and_then(|id| u32::try_from(id).ok()) {
                            ids.insert(id);
                        }
                    }
                }
                for value in object.values() {
                    collect_map_ids_from_json(value, ids);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect_map_ids_from_json(value, ids);
                }
            }
            _ => {}
        }
    }

    fn parse_dispatcher_program_ids(
        text: &str,
        interface: &str,
        program_name: &str,
    ) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        let mut matched_without_id = false;
        let mut current_interface_matches = false;
        for line in text.lines() {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.is_empty() {
                continue;
            }
            if tokens[0] == interface {
                current_interface_matches = true;
            } else if !line.chars().next().is_some_and(|ch| ch.is_whitespace()) {
                current_interface_matches = false;
            }
            if !current_interface_matches || !tokens.iter().any(|token| *token == program_name) {
                continue;
            }
            if let Some(id) = parse_status_program_id(&tokens, program_name) {
                ids.push(id);
            } else {
                matched_without_id = true;
            }
        }
        if matched_without_id {
            bail!(
                "xdp-loader status showed program '{program_name}' on interface '{interface}' but no program id could be parsed; refusing dispatcher attach to avoid duplicate loads"
            );
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    fn parse_status_program_id(tokens: &[&str], program_name: &str) -> Option<u32> {
        for window in tokens.windows(2) {
            let key = window[0].trim_end_matches(':');
            if key.eq_ignore_ascii_case("id") {
                if let Some(id) = parse_u32_token(window[1]) {
                    return Some(id);
                }
            }
        }
        let program_index = tokens.iter().position(|token| *token == program_name)?;
        tokens
            .iter()
            .skip(program_index + 1)
            .find_map(|token| parse_u32_token(token))
    }

    fn parse_u32_token(value: &str) -> Option<u32> {
        value
            .trim_matches(|ch: char| !ch.is_ascii_digit())
            .parse::<u32>()
            .ok()
    }

    fn is_no_dispatcher_output(output: &std::process::Output) -> bool {
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_ascii_lowercase();
        text.contains("no xdp")
            || text.contains("no program")
            || text.contains("not found")
            || text.contains("no such")
            || text.contains("nothing")
    }

    fn xdp_loader_verbose_args<const N: usize>(verbose: u8, args: [&str; N]) -> Vec<String> {
        let mut values = args.into_iter().map(str::to_string).collect::<Vec<_>>();
        for _ in 0..verbose {
            values.push("--verbose".to_string());
        }
        values
    }

    fn run_xdp_loader_command(
        loader_path: &str,
        args: Vec<String>,
    ) -> Result<std::process::Output> {
        std::process::Command::new(loader_path)
            .args(args)
            .output()
            .with_context(|| format!("failed to execute xdp-loader '{loader_path}'"))
    }

    fn print_command_output(output: &std::process::Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stdout.trim().is_empty() {
            println!("{}", stdout.trim_end());
        }
        if !stderr.trim().is_empty() {
            eprintln!("{}", stderr.trim_end());
        }
    }

    fn ensure_success(command: &str, output: &std::process::Output) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{command} failed: status={} stdout='{}' stderr='{}'",
            output.status,
            stdout.trim(),
            stderr.trim()
        )
    }

    fn ensure_no_existing_xdp(interface: &str) -> Result<()> {
        if let Some(existing) = existing_xdp_summary(interface)? {
            bail!(
                "interface '{interface}' already has an XDP program attached ({existing}); refusing to replace it in direct mode. Use --xdp-allow-replace to replace intentionally, or use --xdp-attach-strategy dispatcher to join the libxdp multiprogram chain"
            );
        }
        Ok(())
    }

    pub(super) fn existing_xdp_summary(interface: &str) -> Result<Option<String>> {
        let output = std::process::Command::new("ip")
            .args(["-details", "link", "show", "dev", interface])
            .output()
            .with_context(|| format!("failed to inspect interface '{interface}' with ip"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "failed to inspect interface '{interface}': {}",
                stderr.trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let text = stdout.trim();
        let has_xdp = text.contains(" xdp ")
            || text.contains(" xdpgeneric ")
            || text.contains(" xdpdrv ")
            || text.contains(" xdpoffload ")
            || text.contains("prog/xdp");
        if !has_xdp {
            return Ok(None);
        }
        let summary = text
            .lines()
            .map(str::trim)
            .find(|line| {
                line.contains("xdp")
                    || line.contains("prog/xdp")
                    || line.contains("id ")
                    || line.contains("tag ")
            })
            .unwrap_or("xdp program present")
            .to_string();
        Ok(Some(summary))
    }

    fn rule_key(addr: IpAddr, prefix: u8, protocol: L4Protocol, port: u16) -> RuleKey {
        let family = if addr.is_ipv4() { 4 } else { 6 };
        LpmKey::new(
            lpm_prefix_len(prefix),
            RuleData {
                family,
                proto: proto_code(protocol),
                dport: port.to_be(),
                addr: addr_bytes(addr),
            },
        )
    }

    fn geo_key(addr: IpAddr, prefix: u8) -> GeoKey {
        let family = if addr.is_ipv4() { 4 } else { 6 };
        LpmKey::new(
            lpm_prefix_len(prefix),
            GeoData {
                family,
                pad: [0; 3],
                addr: addr_bytes(addr),
            },
        )
    }

    fn trusted_key(addr: IpAddr, prefix: u8) -> TrustedKey {
        let family = if addr.is_ipv4() { 4 } else { 6 };
        LpmKey::new(
            lpm_prefix_len(prefix),
            TrustedData {
                family,
                pad: [0; 3],
                addr: addr_bytes(addr),
            },
        )
    }

    fn custom_rate_key(protocol: L4Protocol, port: u16) -> CustomRateKey {
        CustomRateKey {
            proto: proto_code(protocol),
            pad: 0,
            dport: port.to_be(),
        }
    }

    fn temp_ban_key(addr: IpAddr, prefix: u8, protocol: L4Protocol, port: u16) -> TempBanKey {
        LpmKey::new(
            lpm_prefix_len(prefix),
            TempBanData {
                family: if addr.is_ipv4() { 4 } else { 6 },
                proto: proto_code(protocol),
                dport: port.to_be(),
                addr: addr_bytes(addr),
            },
        )
    }

    fn rule_key_id(key: &RuleKey) -> (u32, u8, u8, u16, [u8; 16]) {
        let data = key.data();
        (
            key.prefix_len(),
            data.family,
            data.proto,
            data.dport,
            data.addr,
        )
    }

    fn geo_key_id(key: &GeoKey) -> (u32, u8, [u8; 16]) {
        let data = key.data();
        (key.prefix_len(), data.family, data.addr)
    }

    fn trusted_key_id(key: &TrustedKey) -> (u32, u8, [u8; 16]) {
        let data = key.data();
        (key.prefix_len(), data.family, data.addr)
    }

    fn log_written_trusted_cidrs(keys: &[TrustedKey]) {
        if keys.is_empty() {
            return;
        }
        let mut cidrs = keys.iter().map(trusted_key_cidr).collect::<Vec<_>>();
        cidrs.sort();
        info!(
            trusted_cidrs = %cidrs.join(","),
            trusted_cidr_count = cidrs.len(),
            "wrote trusted CIDRs to XDP map"
        );
    }

    fn trusted_key_cidr(key: &TrustedKey) -> String {
        let data = key.data();
        let prefix = key.prefix_len().saturating_sub(32);
        let addr = match data.family {
            4 => IpAddr::V4(Ipv4Addr::new(
                data.addr[0],
                data.addr[1],
                data.addr[2],
                data.addr[3],
            )),
            6 => IpAddr::V6(Ipv6Addr::from(data.addr)),
            _ => IpAddr::V6(Ipv6Addr::from(data.addr)),
        };
        format!("{addr}/{prefix}")
    }

    fn custom_rate_key_id(key: &CustomRateKey) -> (u8, u16) {
        (key.proto, key.dport)
    }

    fn temp_ban_key_id(key: &TempBanKey) -> (u32, u8, u8, u16, [u8; 16]) {
        let data = key.data();
        (
            key.prefix_len(),
            data.family,
            data.proto,
            data.dport,
            data.addr,
        )
    }

    fn lpm_prefix_len(prefix: u8) -> u32 {
        32 + u32::from(prefix)
    }

    fn addr_bytes(addr: IpAddr) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        match addr {
            IpAddr::V4(ip) => bytes[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => bytes.copy_from_slice(&ip.octets()),
        }
        bytes
    }

    fn monotonic_now_ns() -> Result<u64> {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
        let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("failed to read CLOCK_MONOTONIC");
        }
        let ts = unsafe { ts.assume_init() };
        let seconds = u64::try_from(ts.tv_sec).context("CLOCK_MONOTONIC seconds are negative")?;
        let nanos = u64::try_from(ts.tv_nsec).context("CLOCK_MONOTONIC nanos are negative")?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanos))
            .context("CLOCK_MONOTONIC value overflowed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_component_allows_vlan_interface_names() {
        assert_eq!(sanitize_pin_component("eth0.10").unwrap(), "eth0.10");
    }

    #[test]
    fn pin_component_rejects_path_components() {
        for value in ["", " ", ".", ".."] {
            assert!(sanitize_pin_component(value).is_err());
        }
    }

    #[test]
    fn resized_map_sizes_doubles_and_rounds_changed_maps() {
        let current = XdpMapSizes {
            rule_entries: 4,
            geo_entries: 8,
            trusted_entries: 16,
            country_entries: 676,
            rate_entries: 1024,
            custom_rate_limit_entries: 32,
            temp_ban_entries: 64,
        };
        let required = XdpMapSizes {
            rule_entries: 5,
            geo_entries: 8,
            trusted_entries: 40,
            country_entries: 677,
            rate_entries: 999_999,
            custom_rate_limit_entries: 100,
            temp_ban_entries: 64,
        };

        let resized = resized_map_sizes(current, required).unwrap().unwrap();
        assert_eq!(resized.rule_entries, 8);
        assert_eq!(resized.geo_entries, 8);
        assert_eq!(resized.trusted_entries, 64);
        assert_eq!(resized.country_entries, 2048);
        assert_eq!(resized.rate_entries, 1024);
        assert_eq!(resized.custom_rate_limit_entries, 128);
        assert_eq!(resized.temp_ban_entries, 64);
    }

    #[test]
    fn resized_map_sizes_returns_none_when_current_capacity_is_enough() {
        let current = XdpMapSizes::default();
        let mut required = current;
        required.rate_entries = 1;

        assert_eq!(resized_map_sizes(current, required).unwrap(), None);
    }

    #[test]
    fn compact_trusted_prefixes_removes_only_contained_prefixes() {
        let compacted = compact_trusted_prefixes(&[
            XdpTrustedPrefix {
                addr: "172.30.133.54".parse().unwrap(),
                prefix: 32,
            },
            XdpTrustedPrefix {
                addr: "172.30.0.0".parse().unwrap(),
                prefix: 16,
            },
            XdpTrustedPrefix {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 24,
            },
            XdpTrustedPrefix {
                addr: "10.0.1.0".parse().unwrap(),
                prefix: 24,
            },
            XdpTrustedPrefix {
                addr: "fd00::1".parse().unwrap(),
                prefix: 128,
            },
            XdpTrustedPrefix {
                addr: "fd00::".parse().unwrap(),
                prefix: 64,
            },
        ]);

        assert_eq!(
            compacted,
            vec![
                XdpTrustedPrefix {
                    addr: "172.30.0.0".parse().unwrap(),
                    prefix: 16,
                },
                XdpTrustedPrefix {
                    addr: "10.0.0.0".parse().unwrap(),
                    prefix: 24,
                },
                XdpTrustedPrefix {
                    addr: "10.0.1.0".parse().unwrap(),
                    prefix: 24,
                },
                XdpTrustedPrefix {
                    addr: "fd00::".parse().unwrap(),
                    prefix: 64,
                },
            ]
        );
    }

    #[test]
    fn compact_temp_bans_drops_shorter_lived_covered_prefixes() {
        let now = chrono::Utc::now().naive_utc();
        let compacted = compact_temp_bans(&[
            XdpTempBan {
                addr: "203.0.113.10".parse().unwrap(),
                prefix: 32,
                protocol: crate::firewall::L4Protocol::Tcp,
                port: 443,
                expires_at: now + chrono::Duration::seconds(60),
            },
            XdpTempBan {
                addr: "203.0.113.0".parse().unwrap(),
                prefix: 24,
                protocol: crate::firewall::L4Protocol::Tcp,
                port: 443,
                expires_at: now + chrono::Duration::seconds(300),
            },
            XdpTempBan {
                addr: "203.0.113.20".parse().unwrap(),
                prefix: 32,
                protocol: crate::firewall::L4Protocol::Tcp,
                port: 443,
                expires_at: now + chrono::Duration::seconds(600),
            },
            XdpTempBan {
                addr: "203.0.113.10".parse().unwrap(),
                prefix: 32,
                protocol: crate::firewall::L4Protocol::Udp,
                port: 443,
                expires_at: now + chrono::Duration::seconds(60),
            },
        ]);

        assert_eq!(compacted.len(), 3);
        assert!(compacted.iter().any(|ban| {
            ban.addr.to_string() == "203.0.113.0"
                && ban.prefix == 24
                && ban.protocol == crate::firewall::L4Protocol::Tcp
        }));
        assert!(compacted.iter().any(|ban| {
            ban.addr.to_string() == "203.0.113.20"
                && ban.prefix == 32
                && ban.protocol == crate::firewall::L4Protocol::Tcp
        }));
        assert!(compacted.iter().any(|ban| {
            ban.addr.to_string() == "203.0.113.10"
                && ban.prefix == 32
                && ban.protocol == crate::firewall::L4Protocol::Udp
        }));
    }

    #[test]
    fn deny_rule_matching_local_cidr_detects_covering_cidr() {
        let local_cidrs = vec![
            LocalInterfaceCidr {
                ip: "172.30.133.54".parse().unwrap(),
                prefix: 20,
            },
            LocalInterfaceCidr {
                ip: "fd00::1234".parse().unwrap(),
                prefix: 64,
            },
        ];
        let deny_rule = XdpPrefixRule {
            addr: "172.30.0.0".parse().unwrap(),
            prefix: 16,
            priority: 10,
            action: crate::firewall::RuleAction::Deny,
            protocol: crate::firewall::L4Protocol::Any,
            port: 0,
            source: crate::firewall::XdpRuleSource::FirewallRule,
        };
        let allow_rule = XdpPrefixRule {
            action: crate::firewall::RuleAction::Allow,
            ..deny_rule
        };
        let unrelated_deny = XdpPrefixRule {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 8,
            ..deny_rule
        };

        assert_eq!(
            deny_rule_matching_local_cidr(&deny_rule, &local_cidrs),
            Some(LocalInterfaceCidr {
                ip: "172.30.133.54".parse().unwrap(),
                prefix: 20,
            })
        );
        assert_eq!(
            deny_rule_matching_local_cidr(&allow_rule, &local_cidrs),
            None
        );
        assert_eq!(
            deny_rule_matching_local_cidr(&unrelated_deny, &local_cidrs),
            None
        );
    }

    #[test]
    fn temp_ban_matching_local_cidr_detects_covering_cidr() {
        let local_cidrs = vec![LocalInterfaceCidr {
            ip: "203.0.113.10".parse().unwrap(),
            prefix: 24,
        }];
        let ban = XdpTempBan {
            addr: "203.0.113.0".parse().unwrap(),
            prefix: 24,
            protocol: crate::firewall::L4Protocol::Tcp,
            port: 443,
            expires_at: chrono::Utc::now().naive_utc() + chrono::Duration::seconds(300),
        };
        let unrelated = XdpTempBan {
            addr: "198.51.100.0".parse().unwrap(),
            prefix: 24,
            ..ban
        };

        assert_eq!(
            temp_ban_matching_local_cidr(ban, &local_cidrs),
            Some(LocalInterfaceCidr {
                ip: "203.0.113.10".parse().unwrap(),
                prefix: 24,
            })
        );
        assert_eq!(temp_ban_matching_local_cidr(unrelated, &local_cidrs), None);
    }

    #[test]
    fn format_local_interface_cidrs_uses_ip_slash_prefix() {
        assert_eq!(
            format_local_interface_cidrs(&[
                LocalInterfaceCidr {
                    ip: "172.30.133.54".parse().unwrap(),
                    prefix: 20,
                },
                LocalInterfaceCidr {
                    ip: "fd00::1234".parse().unwrap(),
                    prefix: 64,
                },
            ]),
            "172.30.133.54/20,fd00::1234/64"
        );
    }

    #[test]
    fn validate_map_capacity_reports_capacity_shortfall() {
        let current = XdpMapSizes {
            rule_entries: 1,
            ..XdpMapSizes::default()
        };
        let required = XdpMapSizes {
            rule_entries: 2,
            ..current
        };

        let err = validate_map_capacity(required, current).unwrap_err();
        assert!(err.to_string().contains("rule_cidrs needs 2 entries"));
    }
}
