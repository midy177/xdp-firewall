use super::{
    XdsService, internal_status,
    proto::{FetchPolicyRequest, FetchPolicyResponse},
    state::{latest_version, load_xds_snapshot},
};
use tonic::Status;
use tracing::info;

mod geo_prefixes;

pub(in crate::control_plane::xds) use geo_prefixes::fetch_geo_prefixes_response;

pub(in crate::control_plane::xds) async fn fetch_policy_response(
    service: &XdsService,
    request: FetchPolicyRequest,
) -> std::result::Result<FetchPolicyResponse, Status> {
    let version = latest_version(&service.db).await.map_err(internal_status)?;
    if version <= request.current_version && !service.runtime_trusted_cidrs.enabled() {
        return Ok(unchanged_policy_response(version));
    }

    let external_geo_prefixes = request.supports_external_geo_prefixes;
    let (snapshot, runtime_fingerprint) = load_xds_snapshot(
        &service.db,
        &service.runtime_trusted_cidrs,
        !external_geo_prefixes,
    )
    .await
    .map_err(internal_status)?;
    let policy_json = serde_json::to_string(&snapshot).map_err(internal_status)?;
    info!(
        node_id = %request.node_id,
        interface = %request.interface_name,
        requested_version = request.current_version,
        version,
        external_geo_prefixes,
        runtime_fingerprint,
        "xDS returned updated policy"
    );
    Ok(FetchPolicyResponse {
        version,
        unchanged: false,
        policy_json,
        external_geo_prefixes,
        geo_prefix_version: geo_prefix_version(version, external_geo_prefixes),
    })
}

fn unchanged_policy_response(version: i64) -> FetchPolicyResponse {
    FetchPolicyResponse {
        version,
        unchanged: true,
        policy_json: String::new(),
        external_geo_prefixes: false,
        geo_prefix_version: 0,
    }
}

fn geo_prefix_version(version: i64, external_geo_prefixes: bool) -> i64 {
    if external_geo_prefixes { version } else { 0 }
}
