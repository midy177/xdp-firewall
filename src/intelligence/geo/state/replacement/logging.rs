use crate::intelligence::geo::memory::memory_snapshot;
use tracing::debug;

pub(super) fn log_geo_prefix_replacement(
    country: &str,
    prefix_count: i32,
    cidrs_json_bytes: usize,
) {
    let snapshot = memory_snapshot();
    debug!(
        country,
        prefixes = prefix_count,
        cidrs_json_bytes,
        memory_limit = snapshot.memory_limit.as_deref().unwrap_or("-"),
        memory_current = snapshot.memory_current.as_deref().unwrap_or("-"),
        vm_rss = snapshot.vm_rss.as_deref().unwrap_or("-"),
        vm_hwm = snapshot.vm_hwm.as_deref().unwrap_or("-"),
        "GeoIP country CIDR list persisted"
    );
}
