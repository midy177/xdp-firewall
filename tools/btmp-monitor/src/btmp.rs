//! 直接解析 `/var/log/btmp` 中的二进制 utmp 记录。
//!
//! glibc(x86_64/aarch64)的 `struct utmp` 是 384 字节定长记录,本模块按偏移读取
//! `ut_host`(来源 IP 字符串,与 `lastb` 显示同源)与 `ut_tv`(时间戳),
//! 不依赖外部 `lastb` 二进制及其文本输出格式,也因此不受新版 util-linux
//! 移除 last/lastb 的影响。
//!
//! 崩溃等原因导致的尾部半条记录(size % 384 != 0)会被跳过,游标停在最后
//! 一条完整记录之后,写入方补全后下一轮自然读到。

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// glibc `struct utmp` 的定长大小(x86_64/aarch64 一致)。
pub const UTMP_RECORD_SIZE: usize = 384;

const UT_HOST_OFFSET: usize = 76;
const UT_HOST_LEN: usize = 256;
const UT_TV_SEC_OFFSET: usize = 340;
const UT_ADDR_V6_OFFSET: usize = 348;
const UT_ADDR_V6_LEN: usize = 16;

/// 一条解析后的失败登录记录。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FailedAttempt {
    pub ip: IpAddr,
    pub time: DateTime<Utc>,
}

/// 增量读取游标:已读到的字节偏移与文件 inode。
/// inode 变化或文件变短(logrotate 轮转)时从头重读新文件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReadCursor {
    pub inode: u64,
    pub offset: u64,
}

/// 从游标位置增量读取 btmp,返回(新解析的记录, 新游标)。
///
/// 文件不存在时返回错误——btmp 缺失通常意味着系统没有失败登录记账
/// (最小化安装或 musl 环境),应当显式暴露而不是静默当作零记录。
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

    // 轮转检测:inode 变化说明换了新文件;文件比游标短说明被截断/轮转。
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

    // 丢弃尾部不完整记录,游标停在最后一条完整记录之后。
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

/// 解析单条 384 字节记录;取不到合法 IP 或时间戳时丢弃该条。
fn parse_record(record: &[u8]) -> Option<FailedAttempt> {
    let host = field_str(&record[UT_HOST_OFFSET..UT_HOST_OFFSET + UT_HOST_LEN]);
    let ip = match host.trim().parse::<IpAddr>() {
        Ok(ip) => ip,
        // ut_host 为空或非法(个别写入方只填二进制地址)时回退 ut_addr_v6。
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

/// 读取 NUL 结尾的定长字符字段,非法 UTF-8 以替换字符解码。
fn field_str(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// 解析 `ut_addr_v6` 二进制地址。历史数据对 IPv4 的存法不统一:
/// 可能是 IPv4-mapped(::ffff:a.b.c.d),也可能只填低 4 字节;全零视为无地址。
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

    /// 构造一条 384 字节 utmp 记录。
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

    /// 写入临时 btmp 文件并返回路径。文件名带进程号避免并行测试冲突。
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
        // 2026-08-21T00:00:00Z 附近,远离 2038 溢出与负值边界。
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
        // ut_host 非法且 ut_addr_v6 全零:记录被跳过,但游标照常前进。
        let path = write_btmp("noip", &[build_record("localhost", None, ts(), 0)]);
        let (attempts, cursor) = read_attempts(&path, None).unwrap();
        assert!(attempts.is_empty());
        assert_eq!(cursor.offset, UTMP_RECORD_SIZE as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drops_trailing_partial_record() {
        let path = write_btmp("partial", &[build_record("1.2.3.4", None, ts(), 0)]);
        // 追加 100 字节半条记录。
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

        // 模拟轮转:换一个新文件写入同一路径(inode 变化、内容从头开始)。
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
