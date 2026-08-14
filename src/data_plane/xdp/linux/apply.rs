use super::{LinuxXdpManager, XdpAttachStrategy, loader};
use crate::data_plane::xdp::{
    CompiledPolicy, Result, XdpMapSizes, compact_temp_bans, compact_trusted_prefixes,
    resized_map_sizes, usize_to_u32, validate_map_capacity,
};
use anyhow::Context;
use std::collections::HashSet;
use tracing::warn;

mod cleanup;
mod write;

impl LinuxXdpManager {
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
                loader::unload_dispatcher_programs_by_name(
                    &self.attach_options.loader_path,
                    &self.interface,
                    &self.program_name,
                    true,
                )?;
            }
        }
        loader::remove_map_pin_dir(&self.interface)
    }
}
