//! Directly parse the binary utmp records inside `/var/log/btmp`.
//!
//! On glibc (x86_64/aarch64) `struct utmp` is a fixed 384-byte record. This
//! module reads `ut_host` (source IP string, the same field `lastb` displays)
//! and `ut_tv` (timestamp) by offset, without depending on an external `lastb`
//! binary or its text output format — which also makes it immune to newer
//! util-linux releases dropping last/lastb.
//!
//! A trailing partial record (size % 384 != 0, e.g. after a crash) is skipped;
//! the cursor stops after the last complete record and picks the rest up once
//! the writer completes it.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Fixed size of glibc `struct utmp` (identical on x86_64/aarch64).
pub const UTMP_RECORD_SIZE: usize = 384;

const UT_HOST_OFFSET: usize = 76;
const UT_HOST_LEN: usize = 256;
const UT_TV_SEC_OFFSET: usize = 340;
const UT_ADDR_V6_OFFSET: usize = 348;
const UT_ADDR_V6_LEN: usize = 16;

/// One parsed failed-login record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FailedAttempt {
    pub ip: IpAddr,
    pub time: DateTime<Utc>,
}

/// Incremental read cursor: byte offset already read plus the file inode.
/// An inode change or a file shorter than the offset (logrotate rotation)
/// restarts reading from the beginning of the new file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReadCursor {
    pub inode: u64,
    pub offset: u64,
}

/// Incrementally read btmp from the cursor position; returns
/// (newly parsed records, new cursor).
///
/// A missing file is an error — an absent btmp usually means the system has no
/// failed-login accounting at all (minimal install or musl), which should be
/// surfaced explicitly instead of silently treated as zero records.
pub fn read_attempts(
    path: &Path,
    cursor: Option<ReadCursor>,
) -> Result<(Vec<FailedAttempt>, ReadCursor)> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open btmp file: {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("failed to stat btmp file: {}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("btmp path is not a regular file: {}", path.display());
    }
    let inode = meta.ino();

    // Rotation detection: a different inode means a new file; a file shorter
    // than the offset means it was truncated or rotated.
    let start = match cursor {
        Some(c) if c.inode == inode && c.offset <= meta.len() => c.offset,
        _ => 0,
    };
    if start > 0 {
        file.seek(SeekFrom::Start(start))
            .with_context(|| format!("failed to seek btmp file to {start}"))?;
    }

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read btmp file: {}", path.display()))?;

    // Drop a trailing partial record; the cursor stops after the last complete one.
    let complete = buf.len() / UTMP_RECORD_SIZE * UTMP_RECORD_SIZE;
    let attempts = buf[..complete]
        .chunks_exact(UTMP_RECORD_SIZE)
        .filter_map(parse_record)
        .collect();

    Ok((
        attempts,
        ReadCursor {
            inode,
            offset: start + complete as u64,
        },
    ))
}

/// Parse one 384-byte record; drop it when no valid IP or timestamp can be read.
fn parse_record(record: &[u8]) -> Option<FailedAttempt> {
    let host = field_str(&record[UT_HOST_OFFSET..UT_HOST_OFFSET + UT_HOST_LEN]);
    let ip = match host.trim().parse::<IpAddr>() {
        Ok(ip) => ip,
        // Empty or invalid ut_host (some writers fill only the binary address):
        // fall back to ut_addr_v6.
        Err(_) => ip_from_addr_v6(&record[UT_ADDR_V6_OFFSET..UT_ADDR_V6_OFFSET + UT_ADDR_V6_LEN])?,
    };
    let sec = i32::from_ne_bytes(
        record[UT_TV_SEC_OFFSET..UT_TV_SEC_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    let usec = i32::from_ne_bytes(
        record[UT_TV_SEC_OFFSET + 4..UT_TV_SEC_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    let time = DateTime::from_timestamp(i64::from(sec), u32::try_from(usec).unwrap_or(0) * 1000)?;
    Some(FailedAttempt { ip, time })
}

/// Read a NUL-terminated fixed-size character field; invalid UTF-8 decodes
/// with replacement characters.
fn field_str(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// Parse the binary `ut_addr_v6` address. Historical data stores IPv4
/// inconsistently: either IPv4-mapped (::ffff:a.b.c.d) or only the low 4 bytes;
/// all-zero means "no address".
fn ip_from_addr_v6(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let is_v4_mapped =
        bytes[..10].iter().all(|&b| b == 0) && bytes[10] == 0xff && bytes[11] == 0xff;
    let is_v4_compat = bytes[..12].iter().all(|&b| b == 0);
    if is_v4_mapped || is_v4_compat {
        let octets: [u8; 4] = bytes[12..16].try_into().ok()?;
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    let octets: [u8; 16] = bytes[..UT_ADDR_V6_LEN].try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Build one 384-byte utmp record.
    fn build_record(host: &str, addr_v6: Option<[u8; 16]>, sec: i32, usec: i32) -> [u8; 384] {
        let mut record = [0u8; UTMP_RECORD_SIZE];
        record[UT_HOST_OFFSET..UT_HOST_OFFSET + host.len()].copy_from_slice(host.as_bytes());
        record[UT_TV_SEC_OFFSET..UT_TV_SEC_OFFSET + 4].copy_from_slice(&sec.to_ne_bytes());
        record[UT_TV_SEC_OFFSET + 4..UT_TV_SEC_OFFSET + 8].copy_from_slice(&usec.to_ne_bytes());
        if let Some(addr) = addr_v6 {
            record[UT_ADDR_V6_OFFSET..UT_ADDR_V6_OFFSET + UT_ADDR_V6_LEN].copy_from_slice(&addr);
        }
        record
    }

    /// Write a temporary btmp file and return its path; the name embeds the
    /// process id so parallel tests never collide.
    fn write_btmp(name: &str, records: &[[u8; 384]]) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("btmp-monitor-test-{}-{name}", std::process::id()));
        let mut data = Vec::new();
        for record in records {
            data.extend_from_slice(record);
        }
        std::fs::write(&path, &data).unwrap();
        path
    }

    fn append_btmp(path: &Path, record: &[u8; 384]) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(record).unwrap();
    }

    fn ts() -> i32 {
        // Around 2026-08-21T00:00:00Z, far from the 2038 overflow and negative bounds.
        1_787_328_000
    }

    #[test]
    fn parses_v4_host_record() {
        let path = write_btmp("v4", &[build_record("43.160.219.175", None, ts(), 120_000)]);
        let (attempts, cursor) = read_attempts(&path, None).unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].ip.to_string(), "43.160.219.175");
        assert_eq!(attempts[0].time.timestamp(), i64::from(ts()));
        assert_eq!(attempts[0].time.timestamp_subsec_millis(), 120);
        assert_eq!(cursor.offset, UTMP_RECORD_SIZE as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parses_v6_host_record() {
        let path = write_btmp("v6", &[build_record("2001:db8::1", None, ts(), 0)]);
        let (attempts, _) = read_attempts(&path, None).unwrap();
        assert_eq!(attempts[0].ip.to_string(), "2001:db8::1");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drops_record_without_ip() {
        // Invalid ut_host and all-zero ut_addr_v6: the record is skipped but
        // the cursor still advances past it.
        let path = write_btmp("noip", &[build_record("localhost", None, ts(), 0)]);
        let (attempts, cursor) = read_attempts(&path, None).unwrap();
        assert!(attempts.is_empty());
        assert_eq!(cursor.offset, UTMP_RECORD_SIZE as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drops_trailing_partial_record() {
        let path = write_btmp("partial", &[build_record("1.2.3.4", None, ts(), 0)]);
        // Append 100 bytes of a partial record.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[0u8; 100]).unwrap();
        drop(file);

        let (attempts, cursor) = read_attempts(&path, None).unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(cursor.offset, UTMP_RECORD_SIZE as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn incremental_read_returns_only_new_records() {
        let path = write_btmp(
            "incr",
            &[
                build_record("1.1.1.1", None, ts(), 0),
                build_record("2.2.2.2", None, ts(), 0),
            ],
        );
        let (first, cursor) = read_attempts(&path, None).unwrap();
        assert_eq!(first.len(), 2);

        append_btmp(&path, &build_record("3.3.3.3", None, ts(), 0));
        let (second, cursor) = read_attempts(&path, Some(cursor)).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].ip.to_string(), "3.3.3.3");
        assert_eq!(cursor.offset, 3 * UTMP_RECORD_SIZE as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inode_change_rereads_from_start() {
        let path = write_btmp("rotate", &[build_record("1.1.1.1", None, ts(), 0)]);
        let (_, cursor) = read_attempts(&path, None).unwrap();

        // Simulate rotation: write a fresh file and rename it over the path
        // (inode changes, content restarts from the beginning).
        let path2 = write_btmp("rotate-new", &[build_record("9.9.9.9", None, ts(), 0)]);
        std::fs::rename(&path2, &path).unwrap();

        let (attempts, _) = read_attempts(&path, Some(cursor)).unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].ip.to_string(), "9.9.9.9");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn addr_v6_fallback_mapped_v4() {
        // ::ffff:1.2.3.4
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12..16].copy_from_slice(&[1, 2, 3, 4]);
        let path = write_btmp("mapped", &[build_record("", Some(addr), ts(), 0)]);
        let (attempts, _) = read_attempts(&path, None).unwrap();
        assert_eq!(attempts[0].ip.to_string(), "1.2.3.4");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn addr_v6_fallback_raw_v6() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = 1;
        let path = write_btmp("rawv6", &[build_record("", Some(addr), ts(), 0)]);
        let (attempts, _) = read_attempts(&path, None).unwrap();
        assert_eq!(attempts[0].ip.to_string(), "2001::1");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = read_attempts(Path::new("/nonexistent/btmp-monitor-test"), None);
        assert!(err.is_err());
    }
}
