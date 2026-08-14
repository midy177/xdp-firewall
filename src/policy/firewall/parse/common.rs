use crate::policy::model::{L4Protocol, RuleAction};
use anyhow::{Context, Result, bail};

pub(super) fn parse_action(value: &str) -> Result<RuleAction> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok(RuleAction::Allow),
        "deny" | "drop" => Ok(RuleAction::Deny),
        _ => bail!("unsupported firewall action '{value}'"),
    }
}

pub(super) fn parse_protocol(value: &str) -> Result<L4Protocol> {
    match value.to_ascii_lowercase().as_str() {
        "any" => Ok(L4Protocol::Any),
        "tcp" => Ok(L4Protocol::Tcp),
        "udp" => Ok(L4Protocol::Udp),
        "icmp" => Ok(L4Protocol::Icmp),
        _ => bail!("unsupported L4 protocol '{value}'"),
    }
}

pub(super) fn parse_optional_port(value: Option<i32>, label: &str) -> Result<Option<u16>> {
    value
        .map(|port| u16::try_from(port).with_context(|| format!("{label} is outside u16 range")))
        .transpose()
}
