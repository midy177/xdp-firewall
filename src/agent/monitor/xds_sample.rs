use super::public_error;
use crate::{cli::MonitorArgs, control_plane::xds, policy::model::PolicySnapshot};
use serde::Serialize;

pub(super) async fn sample_xds(
    args: &MonitorArgs,
    node_id: &str,
    interface: &str,
) -> XdsMonitorSample {
    let mut client = match xds::XdsClient::connect(xds::XdsClientConfig {
        control_url: args.control_url.clone(),
        agent_token: args.agent_token.clone(),
    })
    .await
    {
        Ok(client) => client,
        Err(err) => {
            return XdsMonitorSample::error(format!("error={}", public_error(&err)));
        }
    };

    match client.fetch_policy(node_id, interface, -1).await {
        Ok(Some((version, snapshot))) => XdsMonitorSample::policy(version, &snapshot),
        Ok(None) => XdsMonitorSample {
            status: "ok".to_string(),
            details: Some("policy=unchanged".to_string()),
            policy: None,
        },
        Err(err) => XdsMonitorSample::error(public_error(&err)),
    }
}

#[derive(Debug, Serialize)]
pub(super) struct XdsMonitorSample {
    pub(super) status: String,
    pub(super) details: Option<String>,
    policy: Option<PolicyMonitorSample>,
}

impl XdsMonitorSample {
    fn policy(version: i64, snapshot: &PolicySnapshot) -> Self {
        let dynamic = &snapshot.dynamic_defense;
        Self {
            status: "ok".to_string(),
            details: Some(format!(
                "policy_version={} rules={} geo_countries={} trusted_cidrs={} temp_bans={} threat_sources={} threat_prefixes={} dynamic_rate_limits={} dynamic_defense={} ip_rate_limit={} flood={}",
                version,
                snapshot.rules.len(),
                snapshot.geo_countries.len(),
                snapshot.trusted_cidrs.len(),
                snapshot.temp_bans.len(),
                snapshot.threat_sources.len(),
                snapshot.threat_prefixes.len(),
                snapshot.dynamic_rate_limits.len(),
                dynamic.enabled,
                dynamic.ip_rate_limit_enabled,
                dynamic.flood_enabled
            )),
            policy: Some(PolicyMonitorSample {
                version,
                rules: snapshot.rules.len(),
                geo_countries: snapshot.geo_countries.len(),
                trusted_cidrs: snapshot.trusted_cidrs.len(),
                temp_bans: snapshot.temp_bans.len(),
                threat_sources: snapshot.threat_sources.len(),
                threat_prefixes: snapshot.threat_prefixes.len(),
                dynamic_rate_limits: snapshot.dynamic_rate_limits.len(),
                dynamic_defense: dynamic.enabled,
                ip_rate_limit: dynamic.ip_rate_limit_enabled,
                flood: dynamic.flood_enabled,
            }),
        }
    }

    fn error(details: String) -> Self {
        Self {
            status: "error".to_string(),
            details: Some(details),
            policy: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct PolicyMonitorSample {
    version: i64,
    rules: usize,
    geo_countries: usize,
    trusted_cidrs: usize,
    temp_bans: usize,
    threat_sources: usize,
    threat_prefixes: usize,
    dynamic_rate_limits: usize,
    dynamic_defense: bool,
    ip_rate_limit: bool,
    flood: bool,
}
