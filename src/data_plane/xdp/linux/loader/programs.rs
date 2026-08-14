use super::*;

pub(in crate::data_plane::xdp::linux) fn unload_dispatcher_programs_by_name(
    loader_path: &str,
    interface: &str,
    program_name: &str,
    tolerate_missing: bool,
) -> Result<()> {
    let ids = dispatcher_program_ids_by_name(loader_path, interface, program_name)?;
    if ids.is_empty() {
        return Ok(());
    }
    info!(
        interface,
        program = program_name,
        count = ids.len(),
        "unloading existing dispatcher program before attach"
    );
    for id in ids {
        let output = run_xdp_loader_command(
            loader_path,
            vec![
                "unload".to_string(),
                "--id".to_string(),
                id.to_string(),
                interface.to_string(),
            ],
        )
        .with_context(|| format!("failed to run xdp-loader unload --id {id} for '{interface}'"))?;
        print_command_output(&output);
        if let Err(err) = ensure_success("xdp-loader unload --id", &output) {
            if tolerate_missing && is_no_dispatcher_output(&output) {
                debug!(
                    interface,
                    program = program_name,
                    id,
                    error = %err,
                    "dispatcher program was already gone during cleanup"
                );
            } else {
                return Err(err);
            }
        }
    }
    Ok(())
}

pub(in crate::data_plane::xdp::linux) fn dispatcher_program_ids_by_name(
    loader_path: &str,
    interface: &str,
    program_name: &str,
) -> Result<Vec<u32>> {
    let output = run_xdp_loader_command(loader_path, vec!["status".to_string()])
        .with_context(|| "failed to run xdp-loader status before dispatcher attach")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "xdp-loader status failed before dispatcher attach: status={} stdout='{}' stderr='{}'",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dispatcher_program_ids(&stdout, interface, program_name)
}

fn parse_dispatcher_program_ids(
    text: &str,
    interface: &str,
    program_name: &str,
) -> Result<Vec<u32>> {
    let mut ids = Vec::new();
    let mut matched_without_id = false;
    let mut current_interface_matches = false;
    for line in text.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }
        if tokens[0] == interface {
            current_interface_matches = true;
        } else if !line.chars().next().is_some_and(|ch| ch.is_whitespace()) {
            current_interface_matches = false;
        }
        if !current_interface_matches || !tokens.iter().any(|token| *token == program_name) {
            continue;
        }
        if let Some(id) = parse_status_program_id(&tokens, program_name) {
            ids.push(id);
        } else {
            matched_without_id = true;
        }
    }
    if matched_without_id {
        bail!(
            "xdp-loader status showed program '{program_name}' on interface '{interface}' but no program id could be parsed; refusing dispatcher attach to avoid duplicate loads"
        );
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

fn parse_status_program_id(tokens: &[&str], program_name: &str) -> Option<u32> {
    for window in tokens.windows(2) {
        let key = window[0].trim_end_matches(':');
        if key.eq_ignore_ascii_case("id")
            && let Some(id) = parse_u32_token(window[1])
        {
            return Some(id);
        }
    }
    let program_index = tokens.iter().position(|token| *token == program_name)?;
    tokens
        .iter()
        .skip(program_index + 1)
        .find_map(|token| parse_u32_token(token))
}

fn parse_u32_token(value: &str) -> Option<u32> {
    value
        .trim_matches(|ch: char| !ch.is_ascii_digit())
        .parse::<u32>()
        .ok()
}
