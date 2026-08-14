use anyhow::{Context, Result, bail};

pub(in crate::control_plane::api) fn normalize_action(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok("allow".to_string()),
        "deny" | "drop" => Ok("deny".to_string()),
        _ => bail!("action must be allow or deny"),
    }
}

pub(in crate::control_plane::api) fn normalize_protocol(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "any" => Ok("any".to_string()),
        "tcp" => Ok("tcp".to_string()),
        "udp" => Ok("udp".to_string()),
        "icmp" => Ok("icmp".to_string()),
        _ => bail!("protocol must be any, tcp, udp, or icmp"),
    }
}

pub(in crate::control_plane::api) fn validate_port(
    protocol: Option<&str>,
    port: Option<i32>,
) -> Result<Option<i32>> {
    let Some(port) = port else {
        return Ok(None);
    };
    u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .context("port must be between 1 and 65535")?;
    match protocol.unwrap_or("any") {
        "any" | "tcp" | "udp" => Ok(Some(port)),
        "icmp" => bail!("icmp rules cannot set a port"),
        other => bail!("unsupported protocol '{other}'"),
    }
}

pub(in crate::control_plane::api) fn validate_dynamic_rate_port(
    protocol: &str,
    port: Option<i32>,
) -> Result<Option<i32>> {
    let Some(port) = port else {
        return Ok(None);
    };
    u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .context("port must be between 1 and 65535")?;
    match protocol {
        "any" | "tcp" | "udp" => Ok(Some(port)),
        "icmp" => bail!("icmp dynamic rate limits cannot set a port"),
        other => bail!("unsupported protocol '{other}'"),
    }
}

pub(in crate::control_plane::api) fn validate_positive_i32(label: &str, value: i32) -> Result<()> {
    if value <= 0 {
        bail!("{label} must be greater than 0");
    }
    Ok(())
}
