use anyhow::{Context, Result};

pub(crate) fn i32_to_u32(label: &str, value: i32) -> Result<u32> {
    u32::try_from(value).with_context(|| format!("{label} is negative"))
}

pub(crate) fn optional_u32_to_i32(label: &str, value: Option<u32>) -> Result<Option<i32>> {
    value
        .map(|value| i32::try_from(value).with_context(|| format!("{label} exceeds i32 range")))
        .transpose()
}

pub(crate) fn optional_i32_to_u32(label: &str, value: Option<i32>) -> Result<Option<u32>> {
    value.map(|value| i32_to_u32(label, value)).transpose()
}
