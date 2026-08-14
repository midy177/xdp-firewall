use anyhow::{Result, bail};

pub(in crate::control_plane::api) fn normalize_rule_key(
    value: Option<String>,
) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 {
        bail!("rule_key must contain at most 128 characters");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("rule_key may only contain letters, numbers, '.', '_', '-', and ':'");
    }
    Ok(Some(value.to_string()))
}
