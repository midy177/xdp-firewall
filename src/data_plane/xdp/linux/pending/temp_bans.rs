use super::super::*;
use super::safety::temp_ban_matches_local_interface;
use std::collections::HashSet;
use tracing::warn;

pub(super) fn pending_temp_bans(
    manager: &LinuxXdpManager,
    bans: &[XdpTempBan],
    wall_now: chrono::NaiveDateTime,
) -> (HashSet<TempBanId>, Vec<(TempBanKey, XdpTempBan)>) {
    let mut ids = HashSet::new();
    let mut pending = Vec::new();
    let temp_bans = compact_temp_bans(bans);
    for ban in &temp_bans {
        collect_temp_ban(manager, *ban, wall_now, &mut ids, &mut pending);
    }
    (ids, pending)
}

fn collect_temp_ban(
    manager: &LinuxXdpManager,
    ban: XdpTempBan,
    wall_now: chrono::NaiveDateTime,
    ids: &mut HashSet<TempBanId>,
    pending: &mut Vec<(TempBanKey, XdpTempBan)>,
) {
    if ban.expires_at <= wall_now || temp_ban_matches_local_interface(manager, ban) {
        return;
    }
    let key = temp_ban_key(ban.addr, ban.prefix, ban.protocol, ban.port);
    if ids.insert(temp_ban_key_id(&key)) {
        pending.push((key, ban));
    } else {
        warn!(
            addr = %ban.addr,
            prefix = ban.prefix,
            protocol = ?ban.protocol,
            port = ban.port,
            "skipping duplicate temporary ban key; first matching key remains active"
        );
    }
}
