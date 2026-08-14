use crate::intelligence::geo::{GeoPrefix, persisted::geo_prefix_from_net};
use ipnet::IpNet;
use tracing::warn;

pub(super) fn parse_ipdeny_line(country: &str, country_code: u16, line: &str) -> Option<GeoPrefix> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let net = match line.parse::<IpNet>() {
        Ok(net) => net,
        Err(err) => {
            warn!(
                country,
                cidr = line,
                error = %err,
                "skipping malformed IPdeny CIDR line"
            );
            return None;
        }
    };
    Some(geo_prefix_from_net(net, country_code))
}
