use super::LinuxXdpManager;
use crate::data_plane::xdp::{
    Result, STAT_CUSTOM_RATE_DROP, STAT_FLOOD_DROP, STAT_GEO_DROP, STAT_PARSE_DROP, STAT_PASS,
    STAT_RATE_DROP, STAT_RULE_DROP, STAT_TEMP_BAN_DROP, XdpStats,
};
use anyhow::Context;

impl LinuxXdpManager {
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
}
