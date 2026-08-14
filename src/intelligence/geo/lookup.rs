use anyhow::{Context, Result};
use maxminddb::{Mmap, Reader, path};
use sea_orm::DatabaseConnection;
use std::{
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tracing::debug;

use super::GeoIpCountry;
use super::memory::log_geo_memory_snapshot;

mod rebuild;

use rebuild::{build_geoip_rebuild_file, load_geo_country_names, log_skipped_ipv6_prefixes};

#[derive(Clone, Default)]
pub struct GeoIpLookup {
    reader: Arc<RwLock<Option<GeoIpDatabase>>>,
}

struct GeoIpDatabase {
    reader: Reader<Mmap>,
    path: PathBuf,
}

struct GeoIpRebuildFile {
    path: PathBuf,
    prefix_count: usize,
}

impl GeoIpLookup {
    pub async fn rebuild_from_db(&self, db: &DatabaseConnection) -> Result<usize> {
        let country_names = load_geo_country_names(db).await?;
        self.clear_reader();

        let (file, skipped_ipv6) = build_geoip_rebuild_file(db, &country_names).await?;
        log_skipped_ipv6_prefixes(skipped_ipv6);
        let Some(file) = file else {
            return Ok(0);
        };

        self.install_reader(file.path)?;
        log_geo_memory_snapshot("after temporary MMDB mmap");
        Ok(file.prefix_count)
    }

    fn install_reader(&self, path: PathBuf) -> Result<()> {
        // SAFETY: the generated file path is unique and is not modified after this mmap is opened.
        let reader = unsafe { Reader::open_mmap(&path) }
            .with_context(|| format!("failed to mmap temporary MMDB {}", path.display()))?;
        *self.reader.write().expect("geoip lookup lock poisoned") =
            Some(GeoIpDatabase { reader, path });
        Ok(())
    }

    fn clear_reader(&self) {
        let old = self
            .reader
            .write()
            .expect("geoip lookup lock poisoned")
            .take();
        drop(old);
    }

    #[must_use]
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.lookup_country_record(ip).map(|country| country.code)
    }

    #[must_use]
    pub fn lookup_country_record(&self, ip: IpAddr) -> Option<GeoIpCountry> {
        let guard = self.reader.read().expect("geoip lookup lock poisoned");
        let database = guard.as_ref()?;
        let result = database.reader.lookup(ip).ok()?;
        let code = result
            .decode_path::<String>(&path!["country", "iso_code"])
            .ok()
            .flatten()?;
        let name = result
            .decode_path::<String>(&path!["country", "names", "en"])
            .ok()
            .flatten();
        Some(GeoIpCountry { code, name })
    }
}

impl Drop for GeoIpDatabase {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            debug!(
                path = %self.path.display(),
                error = %err,
                "failed to remove temporary MMDB"
            );
        }
    }
}
