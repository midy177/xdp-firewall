use crate::cli::{XdpReplaceArgs, XdpStatusArgs, XdpUnloadArgs};
use crate::firewall::CompiledPolicy;
#[cfg(target_os = "linux")]
use crate::firewall::{
    L4Protocol, RuleAction, XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix,
    XdpPrefixRule, XdpRuleSource, XdpTempBan,
};
use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use std::net::IpAddr;

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
    pub run_priority: i32,
    pub loader_path: String,
}

impl Default for XdpAttachOptions {
    fn default() -> Self {
        Self {
            mode: XdpAttachMode::Auto,
            strategy: XdpAttachStrategy::Direct,
            allow_replace: false,
            run_priority: 10,
            loader_path: "xdp-loader".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{Context, bail};
    use aya::{
        Ebpf, EbpfLoader, Pod,
        maps::{
            Array as AyaArray, HashMap as AyaHashMap, IterableMap, LpmTrie, MapData, PerCpuArray,
            PerfEventArray, lpm_trie::Key as LpmKey,
        },
        programs::{Xdp, XdpMode},
    };
    use std::collections::HashSet;
    use std::path::Path;
    use tracing::{debug, info, warn};

    pub struct LinuxXdpManager {
        interface: String,
        _ebpf: Ebpf,
        rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
        geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
        trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
        country_rules: AyaHashMap<MapData, u32, CountryValue>,
        defense_policy: AyaArray<MapData, DefenseValue>,
        custom_rate_limits: AyaHashMap<MapData, CustomRateKey, CustomRateValue>,
        temp_bans: AyaHashMap<MapData, TempBanKey, TempBanValue>,
        drop_config: AyaArray<MapData, DropConfigValue>,
        stats: PerCpuArray<MapData, u64>,
        _drop_events: PerfEventArray<MapData>,
        rule_keys: Vec<RuleKey>,
        geo_keys: Vec<GeoKey>,
        trusted_keys: Vec<TrustedKey>,
        country_keys: Vec<u32>,
        custom_rate_keys: Vec<CustomRateKey>,
        temp_ban_keys: Vec<TempBanKey>,
        map_sizes: XdpMapSizes,
    }

    struct XdpMapBundle {
        rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
        geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
        trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
        country_rules: AyaHashMap<MapData, u32, CountryValue>,
        defense_policy: AyaArray<MapData, DefenseValue>,
        custom_rate_limits: AyaHashMap<MapData, CustomRateKey, CustomRateValue>,
        temp_bans: AyaHashMap<MapData, TempBanKey, TempBanValue>,
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

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    struct TempBanKey {
        family: u8,
        proto: u8,
        dport: u16,
        addr: [u8; 16],
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct TempBanValue {
        expires_at_ns: u64,
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
    unsafe impl Pod for TempBanKey {}
    unsafe impl Pod for TempBanValue {}
    unsafe impl Pod for TrustedValue {}
    unsafe impl Pod for DropConfigValue {}

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
                run_priority: args.xdp_run_priority,
                loader_path: args.xdp_loader_path,
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
                let mut ebpf = load_object_with_pinned_maps(object_path, map_sizes, &pin_dir)?;
                match attach_options.strategy {
                    XdpAttachStrategy::Direct => {
                        if attach_options.allow_replace {
                            warn!(
                                interface,
                                "--xdp-allow-replace only bypasses the pre-attach safety check with the current Aya attach path; it does not force-replace an existing XDP program"
                            );
                        } else {
                            ensure_no_existing_xdp(interface)?;
                        }
                        let program: &mut Xdp = ebpf
                            .program_mut(program_name)
                            .with_context(|| format!("XDP program '{program_name}' is missing"))?
                            .try_into()
                            .with_context(|| format!("program '{program_name}' is not XDP"))?;
                        program.load().context("failed to load XDP program")?;
                        attach_program(program, interface, attach_options.mode)?;
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
                    }
                }
                let mut maps = take_maps(&mut ebpf)?;
                let actual_map_sizes = actual_map_sizes(&maps, map_sizes)?;
                let mut drop_config = maps.drop_config;
                set_drop_config(&mut drop_config, false)?;
                maps.drop_config = drop_config;
                info!(
                    interface,
                    strategy = %attach_options.strategy.as_str(),
                    pin_dir = %pin_dir.display(),
                    "XDP maps ready"
                );

                Ok(Self {
                    interface: interface.to_string(),
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
                    rule_keys: Vec::new(),
                    geo_keys: Vec::new(),
                    trusted_keys: Vec::new(),
                    country_keys: Vec::new(),
                    custom_rate_keys: Vec::new(),
                    temp_ban_keys: Vec::new(),
                    map_sizes: actual_map_sizes,
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

        pub fn apply(&mut self, policy: &CompiledPolicy) -> Result<()> {
            self.validate_policy_capacity(policy)?;
            let mut new_rule_keys = Vec::new();
            let mut new_rule_ids = HashSet::new();
            let mut new_geo_keys = Vec::new();
            let mut new_geo_ids = HashSet::new();
            let mut new_trusted_keys = Vec::new();
            let mut new_trusted_ids = HashSet::new();
            let mut new_country_keys = Vec::new();
            let mut new_country_ids = HashSet::new();
            let mut new_custom_rate_keys = Vec::new();
            let mut new_custom_rate_ids = HashSet::new();
            let mut new_temp_ban_keys = Vec::new();
            let mut new_temp_ban_ids = HashSet::new();

            self.put_dynamic_defense(&policy.dynamic_defense)?;
            let monotonic_now_ns = monotonic_now_ns()?;
            let wall_now = chrono::Utc::now().naive_utc();
            for ban in &policy.temp_bans {
                if ban.expires_at <= wall_now {
                    continue;
                }
                let key = temp_ban_key(ban.addr, ban.protocol, ban.port);
                let id = temp_ban_key_id(&key);
                if new_temp_ban_ids.insert(id) {
                    self.put_temp_ban_key(&key, ban, wall_now, monotonic_now_ns)?;
                    new_temp_ban_keys.push(key);
                } else {
                    warn!(
                        addr = %ban.addr,
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
                    self.put_custom_rate_key(&key, limit)?;
                    new_custom_rate_keys.push(key);
                } else {
                    warn!(
                        protocol = ?limit.protocol,
                        port = limit.port,
                        "skipping duplicate custom dynamic rate-limit key; first matching key remains active"
                    );
                }
            }
            for prefix in &policy.trusted_prefixes {
                let key = trusted_key(prefix.addr, prefix.prefix);
                let id = trusted_key_id(&key);
                if new_trusted_ids.insert(id) {
                    self.put_trusted_key(&key)?;
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
                let key = rule_key(rule.addr, rule.prefix, rule.protocol, rule.port);
                let id = rule_key_id(&key);
                if new_rule_ids.insert(id) {
                    self.put_rule_key(&key, rule)?;
                    new_rule_keys.push(key);
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
                    self.put_geo_key(&key, prefix)?;
                    new_geo_keys.push(key);
                }
            }
            for country in &policy.country_rules {
                let key = country_key(country.country);
                if new_country_ids.insert(key) {
                    self.put_country_key(key, country)?;
                    new_country_keys.push(key);
                }
            }
            self.remove_stale_policy_keys(
                &new_rule_ids,
                &new_geo_ids,
                &new_trusted_ids,
                &new_country_ids,
                &new_custom_rate_ids,
                &new_temp_ban_ids,
            )?;
            self.rule_keys = new_rule_keys;
            self.geo_keys = new_geo_keys;
            self.trusted_keys = new_trusted_keys;
            self.country_keys = new_country_keys;
            self.custom_rate_keys = new_custom_rate_keys;
            self.temp_ban_keys = new_temp_ban_keys;
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

        fn validate_policy_capacity(&self, policy: &CompiledPolicy) -> Result<()> {
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

            ensure_capacity("rule_cidrs", rule_entries, self.map_sizes.rule_entries)?;
            ensure_capacity(
                "trusted_cidrs",
                policy.trusted_prefixes.len(),
                self.map_sizes.trusted_entries,
            )?;
            ensure_capacity(
                "geo_cidrs",
                policy.geo_prefixes.len(),
                self.map_sizes.geo_entries,
            )?;
            ensure_capacity(
                "country_rules",
                country_entries,
                self.map_sizes.country_entries,
            )?;
            ensure_capacity(
                "custom_rate_limits",
                policy.dynamic_rate_limits.len(),
                self.map_sizes.custom_rate_limit_entries,
            )?;
            ensure_capacity(
                "temp_bans",
                policy.temp_bans.len(),
                self.map_sizes.temp_ban_entries,
            )?;
            Ok(())
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
            new_temp_ban_ids: &HashSet<(u8, u8, u16, [u8; 16])>,
        ) -> Result<()> {
            for key in self.rule_keys.drain(..) {
                if !new_rule_ids.contains(&rule_key_id(&key)) {
                    self.rule_cidrs.remove(&key)?;
                }
            }
            for key in self.geo_keys.drain(..) {
                if !new_geo_ids.contains(&geo_key_id(&key)) {
                    self.geo_cidrs.remove(&key)?;
                }
            }
            for key in self.trusted_keys.drain(..) {
                if !new_trusted_ids.contains(&trusted_key_id(&key)) {
                    self.trusted_cidrs.remove(&key)?;
                }
            }
            for key in self.country_keys.drain(..) {
                if !new_country_ids.contains(&key) {
                    self.country_rules.remove(&key)?;
                }
            }
            for key in self.custom_rate_keys.drain(..) {
                if !new_custom_rate_ids.contains(&custom_rate_key_id(&key)) {
                    self.custom_rate_limits.remove(&key)?;
                }
            }
            for key in self.temp_ban_keys.drain(..) {
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
    ) -> Result<()> {
        match attach_mode {
            XdpAttachMode::Auto => {
                if let Err(driver_err) = program.attach(interface, XdpMode::Driver) {
                    info!(
                        interface,
                        error = %driver_err,
                        "driver XDP attach unavailable; using skb mode"
                    );
                    program.attach(interface, XdpMode::Skb).with_context(|| {
                        format!("driver XDP attach failed ({driver_err:#}); skb attach failed")
                    })?;
                    info!(interface, mode = "skb", "XDP program attached");
                } else {
                    info!(interface, mode = "driver", "XDP program attached");
                }
            }
            XdpAttachMode::Driver => {
                program
                    .attach(interface, XdpMode::Driver)
                    .context("failed to attach XDP program in driver mode")?;
                info!(interface, mode = "driver", "XDP program attached");
            }
            XdpAttachMode::Skb => {
                program
                    .attach(interface, XdpMode::Skb)
                    .context("failed to attach XDP program in skb mode")?;
                info!(interface, mode = "skb", "XDP program attached");
            }
        }
        Ok(())
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

    fn temp_ban_key(addr: IpAddr, protocol: L4Protocol, port: u16) -> TempBanKey {
        TempBanKey {
            family: if addr.is_ipv4() { 4 } else { 6 },
            proto: proto_code(protocol),
            dport: port.to_be(),
            addr: addr_bytes(addr),
        }
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

    fn custom_rate_key_id(key: &CustomRateKey) -> (u8, u16) {
        (key.proto, key.dport)
    }

    fn temp_ban_key_id(key: &TempBanKey) -> (u8, u8, u16, [u8; 16]) {
        (key.family, key.proto, key.dport, key.addr)
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

    fn ensure_capacity(map: &str, needed: usize, configured: u32) -> Result<()> {
        if needed > configured as usize {
            bail!("{map} needs {needed} entries but map capacity is {configured}");
        }
        Ok(())
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
}
