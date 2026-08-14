use crate::{
    db::entities::geo_ip_prefix,
    intelligence::geo::{
        memory::log_geo_memory_snapshot, normalize_country, persisted::for_each_persisted_cidr,
    },
};
use anyhow::{Context, Result};
use ipnet::IpNet;
use mmdb_writer::{IpVersion, Value, Writer};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
};
use tracing::{debug, warn};

use super::super::GeoIpRebuildFile;

pub(super) struct GeoIpMmdbBuilder {
    writer: Writer,
    prefix_count: usize,
    skipped_ipv6: usize,
}

impl GeoIpMmdbBuilder {
    pub(super) fn new() -> Self {
        Self {
            writer: Writer::builder("XDP-Firewall-Country")
                .ip_version(IpVersion::V4)
                .build(),
            prefix_count: 0,
            skipped_ipv6: 0,
        }
    }

    pub(super) fn write_page(
        &mut self,
        country_names: &HashMap<String, String>,
        rows: Vec<geo_ip_prefix::Model>,
    ) -> Result<()> {
        for row in rows {
            self.write_country_row(country_names, row)?;
        }
        Ok(())
    }

    pub(super) fn skipped_ipv6(&self) -> usize {
        self.skipped_ipv6
    }

    pub(super) fn into_rebuild_file(self) -> Result<Option<GeoIpRebuildFile>> {
        let Self {
            mut writer,
            prefix_count,
            skipped_ipv6: _,
        } = self;
        if prefix_count == 0 {
            return Ok(None);
        }

        let path = geoip_temp_path();
        write_geoip_mmdb_file(&path, &mut writer)?;
        drop(writer);
        log_geo_memory_snapshot("after temporary MMDB write");
        Ok(Some(GeoIpRebuildFile { path, prefix_count }))
    }

    fn write_country_row(
        &mut self,
        country_names: &HashMap<String, String>,
        row: geo_ip_prefix::Model,
    ) -> Result<()> {
        let country = normalize_country(&row.country)?;
        let country_name = country_names
            .get(&country)
            .cloned()
            .unwrap_or_else(|| country.clone());
        let inserted =
            self.write_country_prefixes(&row, &mmdb_country_value(&country, &country_name));
        log_geoip_country_prefixes(&row, inserted);
        Ok(())
    }

    fn write_country_prefixes(&mut self, row: &geo_ip_prefix::Model, value: &Value) -> usize {
        match for_each_persisted_cidr(row, |cidr| {
            if matches!(cidr, IpNet::V6(_)) {
                self.skipped_ipv6 += 1;
                return Ok(());
            }
            self.writer.insert_value(cidr, value.clone())?;
            self.prefix_count += 1;
            Ok(())
        }) {
            Ok(inserted) => inserted,
            Err(err) => {
                warn!(
                    country = %row.country,
                    error = %err,
                    "skipping malformed persisted GeoIP CIDR list while rebuilding MMDB"
                );
                0
            }
        }
    }
}

fn log_geoip_country_prefixes(row: &geo_ip_prefix::Model, inserted: usize) {
    debug!(
        country = %row.country,
        prefixes = inserted,
        "added country prefixes to MMDB writer"
    );
}

fn write_geoip_mmdb_file(path: &Path, writer: &mut Writer) -> Result<()> {
    // Stream the MMDB straight to disk instead of materializing the whole
    // database in a heap Vec via to_bytes().
    let file = std::fs::File::create(path)
        .with_context(|| format!("failed to create temporary MMDB {}", path.display()))?;
    let mut file = std::io::BufWriter::new(file);
    writer
        .write_to(&mut file)
        .with_context(|| format!("failed to write temporary MMDB {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush temporary MMDB {}", path.display()))
}

fn geoip_temp_path() -> PathBuf {
    let now = chrono::Utc::now();
    std::env::temp_dir().join(format!(
        "xdp-firewall-geoip-{}-{}.mmdb",
        std::process::id(),
        now.timestamp_nanos_opt()
            .unwrap_or_else(|| now.timestamp_micros() * 1_000)
    ))
}

fn mmdb_country_value(code: &str, name: &str) -> Value {
    Value::map([(
        "country",
        Value::map([
            ("iso_code", Value::from(code)),
            ("names", Value::map([("en", Value::from(name))])),
        ]),
    )])
}
