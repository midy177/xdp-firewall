use super::super::{ApiResult, ApiState};
use crate::policy::node_maintenance;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(in crate::control_plane::api) struct NodeMaintenanceResponse {
    deleted: u64,
    max_age_seconds: i64,
}

#[derive(Debug, Deserialize)]
pub(in crate::control_plane::api) struct NodeMaintenanceQuery {
    max_age_seconds: Option<i64>,
}

pub(in crate::control_plane::api) async fn maintain(
    State(state): State<ApiState>,
    Query(query): Query<NodeMaintenanceQuery>,
) -> ApiResult<Json<NodeMaintenanceResponse>> {
    let max_age_seconds =
        node_maintenance::normalize_unhealthy_node_after_seconds(query.max_age_seconds)?;
    let deleted = node_maintenance::prune_unhealthy_nodes(&state.db, max_age_seconds).await?;
    Ok(Json(NodeMaintenanceResponse {
        deleted,
        max_age_seconds,
    }))
}
