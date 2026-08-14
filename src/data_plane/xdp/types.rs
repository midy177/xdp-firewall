use anyhow::{Result, bail};

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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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

fn ensure_nonzero(map: &str, entries: u32) -> Result<()> {
    if entries == 0 {
        bail!("{map} capacity must be greater than 0");
    }
    Ok(())
}
