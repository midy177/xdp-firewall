use std::fs;

use tracing::debug;

#[derive(Debug, Default)]
pub(super) struct MemorySnapshot {
    pub(super) memory_limit: Option<String>,
    pub(super) memory_current: Option<String>,
    pub(super) vm_rss: Option<String>,
    pub(super) vm_hwm: Option<String>,
}

pub(super) fn log_geo_memory_snapshot(event: &'static str) {
    let snapshot = memory_snapshot();
    debug!(
        event,
        memory_limit = snapshot.memory_limit.as_deref().unwrap_or("-"),
        memory_current = snapshot.memory_current.as_deref().unwrap_or("-"),
        vm_rss = snapshot.vm_rss.as_deref().unwrap_or("-"),
        vm_hwm = snapshot.vm_hwm.as_deref().unwrap_or("-"),
        "GeoIP memory snapshot"
    );
}

pub(super) fn memory_snapshot() -> MemorySnapshot {
    let mut snapshot = MemorySnapshot {
        memory_limit: read_trimmed("/sys/fs/cgroup/memory.max")
            .or_else(|| read_trimmed("/sys/fs/cgroup/memory/memory.limit_in_bytes")),
        memory_current: read_trimmed("/sys/fs/cgroup/memory.current")
            .or_else(|| read_trimmed("/sys/fs/cgroup/memory/memory.usage_in_bytes")),
        ..Default::default()
    };

    if let Some(status) = read_trimmed("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                snapshot.vm_rss = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("VmHWM:") {
                snapshot.vm_hwm = Some(value.trim().to_string());
            }
        }
    }
    snapshot
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
