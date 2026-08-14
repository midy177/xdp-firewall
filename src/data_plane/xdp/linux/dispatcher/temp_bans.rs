use super::super::*;
use crate::cli::XdpTempBansArgs;

pub(in crate::data_plane::xdp) fn dispatcher_temp_bans(args: XdpTempBansArgs) -> Result<()> {
    let interface = resolve_interface_name(args.interface.as_deref())?;
    let entries = pinned_temp_bans(&interface)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    print_temp_ban_table(&interface, entries)
}

fn print_temp_ban_table(interface: &str, entries: Vec<PinnedTempBanEntry>) -> Result<()> {
    println!(
        "interface={} pinned_map={} temp_bans={}",
        interface,
        map_pin_dir(interface)?.join("temp_bans").display(),
        entries.len()
    );
    if entries.is_empty() {
        return Ok(());
    }
    println!(
        "{:<45} {:<5} {:<6} {:<20} {:<17} active",
        "cidr", "proto", "port", "expires_at_ns", "remaining_seconds"
    );
    for entry in entries {
        print_temp_ban_entry(&entry);
    }
    Ok(())
}

fn print_temp_ban_entry(entry: &PinnedTempBanEntry) {
    println!(
        "{:<45} {:<5} {:<6} {:<20} {:<17} {}",
        entry.cidr,
        entry.protocol,
        entry.port,
        entry.expires_at_ns,
        entry.remaining_seconds,
        entry.active
    );
}
