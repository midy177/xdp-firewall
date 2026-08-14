use super::super::{ApiError, ApiResult, MAX_BATCH_SIZE};
use std::collections::HashSet;

pub(in crate::control_plane::api) fn validate_batch_len(len: usize) -> ApiResult<()> {
    if len == 0 {
        return Err(ApiError::bad_request("items must not be empty"));
    }
    if len > MAX_BATCH_SIZE {
        return Err(ApiError::bad_request(format!(
            "items must contain at most {MAX_BATCH_SIZE} entries"
        )));
    }
    Ok(())
}

pub(in crate::control_plane::api) fn validate_batch_ids(ids: Vec<i32>) -> ApiResult<Vec<i32>> {
    if ids.is_empty() {
        return Err(ApiError::bad_request("ids must not be empty"));
    }
    if ids.len() > MAX_BATCH_SIZE {
        return Err(ApiError::bad_request(format!(
            "ids must contain at most {MAX_BATCH_SIZE} entries"
        )));
    }
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

pub(in crate::control_plane::api) fn ensure_all_ids_deleted(
    deleted: u64,
    requested: usize,
    not_found: &'static str,
) -> ApiResult<()> {
    if deleted != requested as u64 {
        return Err(ApiError::not_found(not_found));
    }
    Ok(())
}
