use super::super::{LinuxXdpManager, monotonic_now_ns, set_drop_config};
use super::{Result, validate_map_capacity};
use crate::data_plane::xdp::{
    CompiledPolicy, CustomRateKey, GeoKey, RuleKey, TempBanKey, TrustedKey, TrustedValue,
    XdpCountryRule, XdpDynamicDefense, XdpDynamicRateLimit, XdpGeoPrefix, XdpPrefixRule,
    XdpTempBan,
};

use super::super::pending::{build_pending_policy_keys, log_written_trusted_cidrs};

mod values;

use values::{
    country_value, custom_rate_value, defense_value, geo_value, rule_value, temp_ban_value,
};

impl LinuxXdpManager {
    pub(super) fn apply_to_current_maps(&mut self, policy: &CompiledPolicy) -> Result<()> {
        let required = self.required_policy_map_sizes(policy)?;
        validate_map_capacity(required, self.map_sizes)?;
        self.put_dynamic_defense(&policy.dynamic_defense)?;
        let wall_now = chrono::Utc::now().naive_utc();
        let monotonic_now_ns = monotonic_now_ns()?;
        let pending = build_pending_policy_keys(self, policy, wall_now);

        for (key, ban) in &pending.temp_bans {
            self.put_temp_ban_key(key, ban, wall_now, monotonic_now_ns)?;
        }
        for (key, limit) in &pending.custom_rate_limits {
            self.put_custom_rate_key(key, limit)?;
        }
        for key in &pending.trusted_keys {
            self.put_trusted_key(key)?;
        }
        for (key, rule) in &pending.rules {
            self.put_rule_key(key, rule)?;
        }
        for (key, prefix) in &pending.geo_prefixes {
            self.put_geo_key(key, prefix)?;
        }
        for (key, country) in &pending.country_rules {
            self.put_country_key(*key, country)?;
        }
        self.remove_stale_policy_keys(&pending)?;
        log_written_trusted_cidrs(&pending.trusted_keys);
        Ok(())
    }

    pub fn set_drop_monitor_enabled(&mut self, enabled: bool) -> Result<()> {
        set_drop_config(&mut self.drop_config, enabled)
    }

    fn put_dynamic_defense(&mut self, policy: &XdpDynamicDefense) -> Result<()> {
        self.defense_policy.set(0, defense_value(policy), 0)?;
        Ok(())
    }

    fn put_trusted_key(&mut self, key: &TrustedKey) -> Result<()> {
        self.trusted_cidrs
            .insert(key, TrustedValue { value: 1 }, 0)?;
        Ok(())
    }

    fn put_rule_key(&mut self, key: &RuleKey, rule: &XdpPrefixRule) -> Result<()> {
        self.rule_cidrs.insert(key, rule_value(rule), 0)?;
        Ok(())
    }

    fn put_custom_rate_key(
        &mut self,
        key: &CustomRateKey,
        limit: &XdpDynamicRateLimit,
    ) -> Result<()> {
        self.custom_rate_limits
            .insert(key, custom_rate_value(limit), 0)?;
        Ok(())
    }

    fn put_temp_ban_key(
        &mut self,
        key: &TempBanKey,
        ban: &XdpTempBan,
        wall_now: chrono::NaiveDateTime,
        monotonic_now_ns: u64,
    ) -> Result<()> {
        let Some(value) = temp_ban_value(ban, wall_now, monotonic_now_ns)? else {
            return Ok(());
        };
        self.temp_bans.insert(key, value, 0)?;
        Ok(())
    }

    fn put_geo_key(&mut self, key: &GeoKey, prefix: &XdpGeoPrefix) -> Result<()> {
        self.geo_cidrs.insert(key, geo_value(prefix), 0)?;
        Ok(())
    }

    fn put_country_key(&mut self, key: u32, country: &XdpCountryRule) -> Result<()> {
        self.country_rules.insert(key, country_value(country), 0)?;
        Ok(())
    }
}
