use super::*;
use std::collections::HashSet;

const DISPATCHER_REFERENCED_MAPS: &[&str] = &[
    "rule_cidrs",
    "geo_cidrs",
    "trusted_cidrs",
    "country_rules",
    "defense_policy",
    "rate_buckets",
    "custom_rate_limits",
    "temp_bans",
    "drop_config",
    "stats",
    "drop_events",
];

pub(in crate::data_plane::xdp::linux) fn verify_dispatcher_map_identity(
    loader_path: &str,
    bpftool_path: &str,
    interface: &str,
    program_name: &str,
    pin_dir: &Path,
) -> Result<()> {
    let ids = dispatcher_program_ids_by_name(loader_path, interface, program_name)?;
    let [program_id] = ids.as_slice() else {
        bail!(
            "expected exactly one dispatcher program named '{program_name}' on interface '{interface}' after attach, found {}",
            ids.len()
        );
    };
    let program_map_ids = bpftool_program_map_ids(bpftool_path, *program_id)?;
    let expected = pinned_map_ids(pin_dir)?;
    let missing = expected
        .iter()
        .filter(|(_, map_id)| !program_map_ids.contains(map_id))
        .map(|(name, map_id)| format!("{name}:{map_id}"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "dispatcher program id {program_id} is not using pinned XDP maps from '{}'; missing map ids: {}",
            pin_dir.display(),
            missing.join(", ")
        );
    }
    info!(
        interface,
        program = program_name,
        program_id,
        maps = expected.len(),
        "verified dispatcher program uses pinned XDP maps"
    );
    Ok(())
}

fn pinned_map_ids(pin_dir: &Path) -> Result<Vec<(&'static str, u32)>> {
    DISPATCHER_REFERENCED_MAPS
        .iter()
        .map(|name| {
            let path = pin_dir.join(name);
            let map = MapData::from_pin(&path)
                .with_context(|| format!("failed to open pinned XDP map '{}'", path.display()))?;
            let id = map
                .info()
                .with_context(|| format!("failed to inspect pinned XDP map '{}'", path.display()))?
                .id();
            Ok((*name, id))
        })
        .collect()
}

fn bpftool_program_map_ids(bpftool_path: &str, program_id: u32) -> Result<HashSet<u32>> {
    let program_id_arg = program_id.to_string();
    let output = std::process::Command::new(bpftool_path)
        .args(["-j", "prog", "show", "id", &program_id_arg])
        .output()
        .with_context(|| {
            format!("failed to execute bpftool '{bpftool_path}' for dispatcher map verification")
        })?;
    if !output.status.success() {
        bail!(
            "bpftool prog show id {program_id} failed: status={} stdout='{}' stderr='{}'",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let value = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .context("failed to parse bpftool JSON while verifying dispatcher maps")?;
    let mut ids = HashSet::new();
    collect_map_ids_from_json(&value, &mut ids);
    if ids.is_empty() {
        bail!("bpftool did not report any map_ids for dispatcher program id {program_id}");
    }
    Ok(ids)
}

fn collect_map_ids_from_json(value: &serde_json::Value, ids: &mut HashSet<u32>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(map_ids) = object.get("map_ids").and_then(|value| value.as_array()) {
                for id in map_ids {
                    if let Some(id) = id.as_u64().and_then(|id| u32::try_from(id).ok()) {
                        ids.insert(id);
                    }
                }
            }
            for value in object.values() {
                collect_map_ids_from_json(value, ids);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_map_ids_from_json(value, ids);
            }
        }
        _ => {}
    }
}
