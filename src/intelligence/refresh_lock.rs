pub(super) fn lock_owner(now: chrono::NaiveDateTime) -> String {
    format!(
        "{}:{}",
        std::process::id(),
        now.and_utc()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| now.and_utc().timestamp_micros() * 1_000)
    )
}

pub(super) fn lease_is_fresh(
    last_checked_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
    now: chrono::NaiveDateTime,
    stale_seconds: i64,
) -> bool {
    let lease_updated_at = last_checked_at.max(updated_at);
    (now - lease_updated_at).num_seconds() < stale_seconds
}
