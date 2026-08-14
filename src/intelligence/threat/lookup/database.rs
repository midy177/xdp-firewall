use super::mmdb::ThreatIntelDatabaseFile;
use anyhow::{Context, Result};
use maxminddb::{Mmap, Reader, path};
use std::{fs, net::IpAddr, path::PathBuf};
use tracing::warn;

pub(super) struct ThreatIntelDatabase {
    reader: Reader<Mmap>,
    path: PathBuf,
}

impl ThreatIntelDatabase {
    pub(super) fn lookup_source(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        result
            .decode_path::<String>(&path!["source"])
            .ok()
            .flatten()
    }
}

pub(super) fn open_threat_intel_database(
    file: ThreatIntelDatabaseFile,
) -> Result<ThreatIntelDatabase> {
    // SAFETY: the generated file path is unique and is not modified after this mmap is opened.
    let reader = unsafe { Reader::open_mmap(&file.path) }.with_context(|| {
        format!(
            "failed to mmap temporary threat MMDB {}",
            file.path.display()
        )
    })?;
    Ok(ThreatIntelDatabase {
        reader,
        path: file.path,
    })
}

impl Drop for ThreatIntelDatabase {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            warn!(
                path = %self.path.display(),
                error = %err,
                "failed to remove temporary threat MMDB"
            );
        }
    }
}
