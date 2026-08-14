use anyhow::{Context, Result};
use ipnet::IpNet;
use mmdb_writer::Value as MmdbValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static THREAT_INTEL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct ThreatIntelDatabaseFile {
    pub(super) path: PathBuf,
    pub(super) prefix_count: usize,
}

pub(super) fn build_threat_intel_database_file(
    sources_by_cidr: BTreeMap<String, BTreeSet<String>>,
) -> Result<ThreatIntelDatabaseFile> {
    let mut writer = mmdb_writer::Writer::builder("XDP-Firewall-Threat-Intel").build();
    let mut count = 0_usize;
    for (cidr, sources) in sources_by_cidr {
        let net = cidr
            .parse::<IpNet>()
            .with_context(|| format!("invalid persisted threat CIDR '{cidr}'"))?;
        let source = sources.into_iter().collect::<Vec<_>>().join(",");
        writer.insert_value(net, threat_source_value(&source))?;
        count += 1;
    }

    let path = threat_intel_temp_path();
    write_threat_intel_mmdb_file(&path, &mut writer)?;
    drop(writer);
    Ok(ThreatIntelDatabaseFile {
        path,
        prefix_count: count,
    })
}

fn write_threat_intel_mmdb_file(path: &Path, writer: &mut mmdb_writer::Writer) -> Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("failed to create temporary threat MMDB {}", path.display()))?;
    let mut file = std::io::BufWriter::new(file);
    writer
        .write_to(&mut file)
        .with_context(|| format!("failed to write temporary threat MMDB {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush temporary threat MMDB {}", path.display()))
}

fn threat_source_value(source: &str) -> MmdbValue {
    MmdbValue::map([("source", MmdbValue::from(source))])
}

fn threat_intel_temp_path() -> PathBuf {
    let sequence = THREAT_INTEL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "xdp-firewall-threat-{}-{}-{}.mmdb",
        std::process::id(),
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp_micros() * 1_000),
        sequence
    ))
}
