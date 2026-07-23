use crate::firewall::CompiledPolicy;
#[cfg(target_os = "linux")]
use crate::firewall::{L4Protocol, RuleAction, XdpCountryRule, XdpGeoPrefix, XdpPrefixRule};
use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use std::net::IpAddr;

pub const DEFAULT_RULE_MAP_ENTRIES: u32 = 262_144;
pub const DEFAULT_GEO_MAP_ENTRIES: u32 = 262_144;
pub const DEFAULT_TRUSTED_MAP_ENTRIES: u32 = 4_096;
pub const DEFAULT_COUNTRY_MAP_ENTRIES: u32 = 676;
pub const DEFAULT_RATE_MAP_ENTRIES: u32 = 1_048_576;

#[derive(Debug, Clone, Copy)]
pub struct XdpMapSizes {
    pub rule_entries: u32,
    pub geo_entries: u32,
    pub trusted_entries: u32,
    pub country_entries: u32,
    pub rate_entries: u32,
}

impl Default for XdpMapSizes {
    fn default() -> Self {
        Self {
            rule_entries: DEFAULT_RULE_MAP_ENTRIES,
            geo_entries: DEFAULT_GEO_MAP_ENTRIES,
            trusted_entries: DEFAULT_TRUSTED_MAP_ENTRIES,
            country_entries: DEFAULT_COUNTRY_MAP_ENTRIES,
            rate_entries: DEFAULT_RATE_MAP_ENTRIES,
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

pub struct XdpManager {
    #[cfg(target_os = "linux")]
    inner: linux::LinuxXdpManager,
}

impl XdpManager {
    pub fn attach(
        interface: Option<&str>,
        object_path: &str,
        program_name: &str,
        map_sizes: XdpMapSizes,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let map_sizes = map_sizes.validate()?;
            let interface = resolve_interface(interface)?;
            return Ok(Self {
                inner: linux::LinuxXdpManager::attach(
                    &interface,
                    object_path,
                    program_name,
                    map_sizes,
                )?,
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (interface, object_path, program_name, map_sizes);
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
}

#[cfg(target_os = "linux")]
fn resolve_interface(configured: Option<&str>) -> Result<String> {
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
        maps::{HashMap as AyaHashMap, LpmTrie, MapData, lpm_trie::Key as LpmKey},
        programs::{Xdp, XdpMode},
    };
    use std::collections::HashSet;
    use std::path::Path;

    pub struct LinuxXdpManager {
        interface: String,
        _ebpf: Ebpf,
        rule_cidrs: LpmTrie<MapData, RuleData, RuleValue>,
        geo_cidrs: LpmTrie<MapData, GeoData, GeoValue>,
        trusted_cidrs: LpmTrie<MapData, TrustedData, TrustedValue>,
        country_rules: AyaHashMap<MapData, u32, CountryValue>,
        rule_keys: Vec<RuleKey>,
        geo_keys: Vec<GeoKey>,
        trusted_keys: Vec<TrustedKey>,
        country_keys: Vec<u32>,
        map_sizes: XdpMapSizes,
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
        priority: u32,
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
        packets_per_second: u32,
        burst: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct TrustedValue {
        value: u8,
    }

    unsafe impl Pod for RuleData {}
    unsafe impl Pod for GeoData {}
    unsafe impl Pod for TrustedData {}
    unsafe impl Pod for RuleValue {}
    unsafe impl Pod for GeoValue {}
    unsafe impl Pod for CountryValue {}
    unsafe impl Pod for TrustedValue {}

    impl LinuxXdpManager {
        pub fn attach(
            interface: &str,
            object_path: &str,
            program_name: &str,
            map_sizes: XdpMapSizes,
        ) -> Result<Self> {
            if !Path::new(object_path).exists() {
                bail!("XDP object '{}' does not exist", object_path);
            }
            let mut loader = EbpfLoader::new();
            loader
                .map_max_entries("rule_cidrs", map_sizes.rule_entries)
                .map_max_entries("geo_cidrs", map_sizes.geo_entries)
                .map_max_entries("trusted_cidrs", map_sizes.trusted_entries)
                .map_max_entries("country_rules", map_sizes.country_entries)
                .map_max_entries("rate_buckets", map_sizes.rate_entries);
            let mut ebpf = loader
                .load_file(object_path)
                .with_context(|| format!("failed to load XDP object '{object_path}'"))?;
            let program: &mut Xdp = ebpf
                .program_mut(program_name)
                .with_context(|| format!("XDP program '{program_name}' is missing"))?
                .try_into()
                .with_context(|| format!("program '{program_name}' is not XDP"))?;
            program.load().context("failed to load XDP program")?;
            if let Err(driver_err) = program.attach(interface, XdpMode::Driver) {
                program.attach(interface, XdpMode::Skb).with_context(|| {
                    format!("driver XDP attach failed ({driver_err:#}); skb attach failed")
                })?;
            }
            let rule_cidrs = ebpf
                .take_map("rule_cidrs")
                .context("missing XDP map 'rule_cidrs'")?
                .try_into()
                .context("XDP map 'rule_cidrs' has unexpected type")?;
            let geo_cidrs = ebpf
                .take_map("geo_cidrs")
                .context("missing XDP map 'geo_cidrs'")?
                .try_into()
                .context("XDP map 'geo_cidrs' has unexpected type")?;
            let country_rules = ebpf
                .take_map("country_rules")
                .context("missing XDP map 'country_rules'")?
                .try_into()
                .context("XDP map 'country_rules' has unexpected type")?;
            let trusted_cidrs = ebpf
                .take_map("trusted_cidrs")
                .context("missing XDP map 'trusted_cidrs'")?
                .try_into()
                .context("XDP map 'trusted_cidrs' has unexpected type")?;

            Ok(Self {
                interface: interface.to_string(),
                _ebpf: ebpf,
                rule_cidrs,
                geo_cidrs,
                trusted_cidrs,
                country_rules,
                rule_keys: Vec::new(),
                geo_keys: Vec::new(),
                trusted_keys: Vec::new(),
                country_keys: Vec::new(),
                map_sizes,
            })
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

            for prefix in &policy.trusted_prefixes {
                let key = trusted_key(prefix.addr, prefix.prefix);
                let id = trusted_key_id(&key);
                if new_trusted_ids.insert(id) {
                    self.put_trusted_key(&key)?;
                    new_trusted_keys.push(key);
                }
            }
            for (priority, rule) in policy
                .rules
                .iter()
                .chain(policy.threat_prefixes.iter())
                .enumerate()
            {
                let key = rule_key(rule.addr, rule.prefix, rule.protocol, rule.port);
                let id = rule_key_id(&key);
                if new_rule_ids.insert(id) {
                    self.put_rule_key(&key, rule, priority as u32)?;
                    new_rule_keys.push(key);
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
            )?;
            self.rule_keys = new_rule_keys;
            self.geo_keys = new_geo_keys;
            self.trusted_keys = new_trusted_keys;
            self.country_keys = new_country_keys;
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
            Ok(())
        }

        fn put_trusted_key(&mut self, key: &TrustedKey) -> Result<()> {
            self.trusted_cidrs
                .insert(key, TrustedValue { value: 1 }, 0)?;
            Ok(())
        }

        fn put_rule_key(
            &mut self,
            key: &RuleKey,
            rule: &XdpPrefixRule,
            priority: u32,
        ) -> Result<()> {
            self.rule_cidrs.insert(
                key,
                RuleValue {
                    action: action_code(rule.action),
                    priority,
                },
                0,
            )?;
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
                    packets_per_second: country.packets_per_second,
                    burst: country.burst,
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
            Ok(())
        }
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
}
