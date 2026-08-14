use super::model::{DynamicDefensePolicy, DynamicRateLimitPolicy, L4Protocol, TempBanPolicy};
use anyhow::{Result, bail};

pub(crate) fn validate_dynamic_defense_policy(policy: &DynamicDefensePolicy) -> Result<()> {
    if !policy.enabled {
        return Ok(());
    }
    if policy.ip_rate_limit_enabled {
        require_positive_dynamic_value(
            "dynamic defense ip packets_per_second",
            policy.ip_packets_per_second,
        )?;
        require_positive_dynamic_value("dynamic defense ip burst", policy.ip_burst)?;
    }
    if policy.flood_enabled {
        require_positive_dynamic_value(
            "dynamic defense flood packets_per_second",
            policy.flood_packets_per_second,
        )?;
        require_positive_dynamic_value("dynamic defense flood burst", policy.flood_burst)?;
        require_positive_dynamic_value(
            "dynamic defense flood block seconds",
            policy.flood_block_seconds,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_dynamic_rate_limit_policy(policy: &DynamicRateLimitPolicy) -> Result<()> {
    if policy.packets_per_second == 0 {
        bail!("dynamic rate limit packets_per_second must be greater than 0");
    }
    if policy.burst == 0 {
        bail!("dynamic rate limit burst must be greater than 0");
    }
    if matches!(policy.protocol, L4Protocol::Icmp) && policy.port.is_some() {
        bail!("dynamic rate limit icmp cannot set a port");
    }
    Ok(())
}

pub(crate) fn validate_temp_ban_policy(policy: &TempBanPolicy) -> Result<()> {
    if matches!(policy.protocol, L4Protocol::Icmp) && policy.port.is_some() {
        bail!("temporary ban icmp cannot set a port");
    }
    Ok(())
}

fn require_positive_dynamic_value(name: &str, value: Option<u32>) -> Result<()> {
    match value {
        Some(value) if value > 0 => Ok(()),
        Some(_) => bail!("{name} must be greater than 0 when dynamic defense is enabled"),
        None => bail!("{name} must be set when dynamic defense is enabled"),
    }
}

#[cfg(test)]
mod tests;
