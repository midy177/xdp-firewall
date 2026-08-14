use super::*;

pub(in crate::data_plane::xdp::linux) fn is_no_dispatcher_output(
    output: &std::process::Output,
) -> bool {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    text.contains("no xdp")
        || text.contains("no program")
        || text.contains("not found")
        || text.contains("no such")
        || text.contains("nothing")
}

pub(in crate::data_plane::xdp::linux) fn xdp_loader_verbose_args<const N: usize>(
    verbose: u8,
    args: [&str; N],
) -> Vec<String> {
    let mut values = args.into_iter().map(str::to_string).collect::<Vec<_>>();
    for _ in 0..verbose {
        values.push("--verbose".to_string());
    }
    values
}

pub(in crate::data_plane::xdp::linux) fn run_xdp_loader_command(
    loader_path: &str,
    args: Vec<String>,
) -> Result<std::process::Output> {
    std::process::Command::new(loader_path)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute xdp-loader '{loader_path}'"))
}

pub(in crate::data_plane::xdp::linux) fn print_command_output(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }
    if !stderr.trim().is_empty() {
        eprintln!("{}", stderr.trim_end());
    }
}

pub(in crate::data_plane::xdp::linux) fn ensure_success(
    command: &str,
    output: &std::process::Output,
) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{command} failed: status={} stdout='{}' stderr='{}'",
        output.status,
        stdout.trim(),
        stderr.trim()
    )
}
