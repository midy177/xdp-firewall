use crate::data_plane::xdp::{
    CustomRateId, GeoId, Result, RuleId, TempBanId, TrustedId, custom_rate_key_id, geo_key_id,
    rule_key_id, temp_ban_key_id, trusted_key_id,
};
use anyhow::Context;
use std::collections::HashSet;

use super::super::{LinuxXdpManager, pending::PendingPolicyKeys};

impl LinuxXdpManager {
    pub(super) fn remove_stale_policy_keys(
        &mut self,
        pending: &PendingPolicyKeys<'_>,
    ) -> Result<()> {
        self.remove_stale_rule_keys(&pending.rule_ids)?;
        self.remove_stale_geo_keys(&pending.geo_ids)?;
        self.remove_stale_trusted_keys(&pending.trusted_ids)?;
        self.remove_stale_country_keys(&pending.country_ids)?;
        self.remove_stale_custom_rate_keys(&pending.custom_rate_ids)?;
        self.remove_stale_temp_ban_keys(&pending.temp_ban_ids)?;
        Ok(())
    }

    fn remove_stale_rule_keys(&mut self, pending_ids: &HashSet<RuleId>) -> Result<()> {
        let rule_keys = self
            .rule_cidrs
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list rule_cidrs keys")?;
        for key in rule_keys {
            if !pending_ids.contains(&rule_key_id(&key)) {
                self.rule_cidrs.remove(&key)?;
            }
        }
        Ok(())
    }

    fn remove_stale_geo_keys(&mut self, pending_ids: &HashSet<GeoId>) -> Result<()> {
        let geo_keys = self
            .geo_cidrs
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list geo_cidrs keys")?;
        for key in geo_keys {
            if !pending_ids.contains(&geo_key_id(&key)) {
                self.geo_cidrs.remove(&key)?;
            }
        }
        Ok(())
    }

    fn remove_stale_trusted_keys(&mut self, pending_ids: &HashSet<TrustedId>) -> Result<()> {
        let trusted_keys = self
            .trusted_cidrs
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list trusted_cidrs keys")?;
        for key in trusted_keys {
            if !pending_ids.contains(&trusted_key_id(&key)) {
                self.trusted_cidrs.remove(&key)?;
            }
        }
        Ok(())
    }

    fn remove_stale_country_keys(&mut self, pending_ids: &HashSet<u32>) -> Result<()> {
        let country_keys = self
            .country_rules
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list country_rules keys")?;
        for key in country_keys {
            if !pending_ids.contains(&key) {
                self.country_rules.remove(&key)?;
            }
        }
        Ok(())
    }

    fn remove_stale_custom_rate_keys(&mut self, pending_ids: &HashSet<CustomRateId>) -> Result<()> {
        let custom_rate_keys = self
            .custom_rate_limits
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list custom_rate_limits keys")?;
        for key in custom_rate_keys {
            if !pending_ids.contains(&custom_rate_key_id(&key)) {
                self.custom_rate_limits.remove(&key)?;
            }
        }
        Ok(())
    }

    fn remove_stale_temp_ban_keys(&mut self, pending_ids: &HashSet<TempBanId>) -> Result<()> {
        let temp_ban_keys = self
            .temp_bans
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list temp_bans keys")?;
        for key in temp_ban_keys {
            if !pending_ids.contains(&temp_ban_key_id(&key)) {
                self.temp_bans.remove(&key)?;
            }
        }
        Ok(())
    }
}
