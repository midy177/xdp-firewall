use super::{DropEventHub, DropEventView};
use crate::intelligence::{geo, threat};
use sea_orm::DatabaseConnection;
use std::net::IpAddr;
use tonic::{Status, Streaming};

use super::super::proto::DropEvent;

pub(in crate::control_plane::xds) async fn accept_reported_drop_events(
    db: &DatabaseConnection,
    hub: &DropEventHub,
    geo_lookup: &geo::GeoIpLookup,
    threat_lookup: &threat::ThreatIntelLookup,
    mut stream: Streaming<DropEvent>,
) -> Result<u64, Status> {
    let mut accepted = 0_u64;
    while let Some(event) = stream.message().await? {
        hub.publish(build_drop_event_view(db, geo_lookup, threat_lookup, event).await);
        accepted += 1;
    }
    Ok(accepted)
}

async fn build_drop_event_view(
    db: &DatabaseConnection,
    geo_lookup: &geo::GeoIpLookup,
    threat_lookup: &threat::ThreatIntelLookup,
    event: DropEvent,
) -> DropEventView {
    let src_ip = event.src.parse().ok();
    let country = reported_country(&event, src_ip, geo_lookup);
    let threat_source = threat_source_for_event(db, threat_lookup, &event, src_ip).await;

    DropEventView {
        node_id: event.node_id,
        interface_name: event.interface_name,
        time: event.time,
        event_time_ns: event.event_time_ns,
        cpu: event.cpu,
        reason: event.reason,
        src: event.src,
        family: event.family,
        proto: event.proto,
        dport: event.dport,
        country,
        threat_source,
        action: event.action,
    }
}

fn reported_country(
    event: &DropEvent,
    src_ip: Option<IpAddr>,
    geo_lookup: &geo::GeoIpLookup,
) -> Option<String> {
    (!event.country.trim().is_empty())
        .then(|| event.country.trim().to_ascii_uppercase())
        .or_else(|| src_ip.and_then(|ip| geo_lookup.lookup_country(ip)))
}

async fn threat_source_for_event(
    db: &DatabaseConnection,
    threat_lookup: &threat::ThreatIntelLookup,
    event: &DropEvent,
    src_ip: Option<IpAddr>,
) -> Option<String> {
    if event.reason != "threat_intel" {
        return None;
    }
    threat_lookup.lookup_source(db, src_ip?).await
}
