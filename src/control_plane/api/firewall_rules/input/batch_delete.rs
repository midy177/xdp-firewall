use super::normalize_rule_key;
use crate::control_plane::api::{ApiError, ApiResult, MAX_BATCH_SIZE};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct RuleBatchDeleteRequest {
    #[serde(default)]
    pub(super) ids: Vec<i32>,
    #[serde(default)]
    pub(super) rule_keys: Vec<String>,
}

pub(in crate::control_plane::api) fn validate_batch_delete_request(
    request: RuleBatchDeleteRequest,
) -> ApiResult<(Vec<i32>, Vec<String>)> {
    let mut entries = request.ids.len();
    let ids = validate_optional_batch_ids(request.ids)?;
    let rule_keys = normalized_rule_keys(request.rule_keys, &mut entries)?;

    if entries == 0 {
        return Err(ApiError::bad_request("ids or rule_keys must not be empty"));
    }
    if !ids.is_empty() && !rule_keys.is_empty() {
        return Err(ApiError::bad_request(
            "ids and rule_keys cannot be used together",
        ));
    }
    if entries > MAX_BATCH_SIZE {
        return Err(ApiError::bad_request(format!(
            "ids and rule_keys must contain at most {MAX_BATCH_SIZE} entries"
        )));
    }

    Ok((ids, rule_keys))
}

fn validate_optional_batch_ids(ids: Vec<i32>) -> ApiResult<Vec<i32>> {
    let mut seen = HashSet::with_capacity(ids.len());
    let mut unique = Vec::with_capacity(ids.len());
    for id in ids {
        if id <= 0 {
            return Err(ApiError::bad_request("ids must be positive integers"));
        }
        if seen.insert(id) {
            unique.push(id);
        }
    }
    Ok(unique)
}

fn normalized_rule_keys(rule_keys: Vec<String>, entries: &mut usize) -> ApiResult<Vec<String>> {
    let mut seen = HashSet::with_capacity(rule_keys.len());
    let mut normalized = Vec::with_capacity(rule_keys.len());

    for rule_key in rule_keys {
        let Some(rule_key) = normalize_rule_key(Some(rule_key))? else {
            continue;
        };
        *entries += 1;
        if seen.insert(rule_key.clone()) {
            normalized.push(rule_key);
        }
    }

    Ok(normalized)
}
