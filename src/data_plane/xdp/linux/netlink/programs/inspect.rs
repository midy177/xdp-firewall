use crate::data_plane::xdp::XdpAttachMode;

pub(super) fn find_xdp_program_id(value: &serde_json::Value, mode: XdpAttachMode) -> Option<u32> {
    let mut mode_specific = Vec::new();
    let mut generic = Vec::new();
    collect_xdp_program_ids(value, mode, &mut mode_specific, &mut generic);
    mode_specific
        .into_iter()
        .next()
        .or_else(|| (generic.len() == 1).then_some(generic[0]))
}

fn collect_xdp_program_ids(
    value: &serde_json::Value,
    mode: XdpAttachMode,
    mode_specific: &mut Vec<u32>,
    generic: &mut Vec<u32>,
) {
    match value {
        serde_json::Value::Object(object) => {
            collect_direct_program_id_fields(object, mode, mode_specific, generic);
            collect_mode_hinted_program_id(object, mode, mode_specific);
            for value in object.values() {
                collect_xdp_program_ids(value, mode, mode_specific, generic);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_xdp_program_ids(value, mode, mode_specific, generic);
            }
        }
        _ => {}
    }
}

fn collect_direct_program_id_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    mode: XdpAttachMode,
    mode_specific: &mut Vec<u32>,
    generic: &mut Vec<u32>,
) {
    for (key, value) in object {
        if let Some(id) = value.as_u64().and_then(|id| u32::try_from(id).ok()) {
            match key.as_str() {
                "drv_prog_id" if mode == XdpAttachMode::Driver => mode_specific.push(id),
                "skb_prog_id" if mode == XdpAttachMode::Skb => mode_specific.push(id),
                "prog_id" => generic.push(id),
                _ => {}
            }
        }
    }
}

fn collect_mode_hinted_program_id(
    object: &serde_json::Map<String, serde_json::Value>,
    mode: XdpAttachMode,
    mode_specific: &mut Vec<u32>,
) {
    let mode_hint = object
        .get("mode")
        .or_else(|| object.get("attached"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let Some(id) = object
        .get("prog_id")
        .and_then(|value| value.as_u64())
        .and_then(|id| u32::try_from(id).ok())
    else {
        return;
    };
    if mode_hint_matches(mode, &mode_hint) {
        mode_specific.push(id);
    }
}

fn mode_hint_matches(mode: XdpAttachMode, mode_hint: &str) -> bool {
    match mode {
        XdpAttachMode::Driver => {
            mode_hint.contains("drv")
                || mode_hint.contains("driver")
                || mode_hint.contains("native")
        }
        XdpAttachMode::Skb => mode_hint.contains("skb") || mode_hint.contains("generic"),
        XdpAttachMode::Auto => false,
    }
}
