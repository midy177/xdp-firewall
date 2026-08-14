use super::super::{
    AUTO_REFRESH_INTERVAL, THREAT_MISSING_PREFIX_POLL_INTERVAL,
    refresh::{GeoIpRefresh, ThreatSourceRefresh},
};
use crate::{
    intelligence::{geo, threat},
    policy::node_maintenance,
};
use sea_orm::DatabaseConnection;
use std::time::Duration;
use tracing::{info, warn};

pub(super) fn start_background_tasks(
    db: &DatabaseConnection,
    geo_lookup: &geo::GeoIpLookup,
) -> threat::ThreatIntelLookup {
    let geo_ip_refresh = GeoIpRefresh::new(AUTO_REFRESH_INTERVAL, geo_lookup.clone());
    spawn_geo_refresh_loop(db.clone(), geo_ip_refresh, AUTO_REFRESH_INTERVAL);

    let threat_lookup = threat::ThreatIntelLookup::default();
    threat_lookup.spawn_rebuild(db.clone());
    let threat_source_refresh =
        ThreatSourceRefresh::new(AUTO_REFRESH_INTERVAL, threat_lookup.clone());
    spawn_threat_refresh_loop(
        db.clone(),
        threat_source_refresh,
        THREAT_MISSING_PREFIX_POLL_INTERVAL,
    );

    spawn_node_maintenance_loop(
        db.clone(),
        Duration::from_secs(node_maintenance::NODE_MAINTENANCE_INTERVAL_SECONDS),
    );
    threat_lookup
}

fn spawn_geo_refresh_loop(
    db: DatabaseConnection,
    geo_ip_refresh: GeoIpRefresh,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = geo_ip_refresh.maybe_run(&db).await {
                warn!(error = %err, "country IP background refresh trigger failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

fn spawn_threat_refresh_loop(
    db: DatabaseConnection,
    threat_source_refresh: ThreatSourceRefresh,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = threat_source_refresh.maybe_run(&db).await {
                warn!(error = %err, "threat intelligence background refresh trigger failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

fn spawn_node_maintenance_loop(db: DatabaseConnection, interval: Duration) {
    tokio::spawn(async move {
        loop {
            match node_maintenance::prune_unhealthy_nodes(
                &db,
                node_maintenance::DEFAULT_UNHEALTHY_NODE_AFTER_SECONDS,
            )
            .await
            {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "pruned unhealthy node heartbeat records");
                }
                Ok(_) => {}
                Err(err) => warn!(error = %err, "node maintenance failed"),
            }
            tokio::time::sleep(interval).await;
        }
    });
}
