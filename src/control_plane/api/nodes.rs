use super::{
    ApiError, ApiResult, ApiState, current_policy_version,
    pagination::{Page, PaginationQuery},
};
use crate::db::entities::node;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use sea_orm::{EntityTrait, PaginatorTrait, QueryOrder};

mod maintenance;
mod response;

pub(super) use maintenance::maintain;
use response::NodeResponse;

pub(super) async fn list(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<Page<NodeResponse>>> {
    let pagination = query.normalize()?;
    let current_version = current_policy_version(&state.db).await?;
    let now = chrono::Utc::now().naive_utc();
    let paginator = node::Entity::find()
        .order_by_asc(node::Column::NodeId)
        .paginate(&state.db, pagination.size);
    let total = paginator.num_items().await?;
    let items = paginator
        .fetch_page(pagination.number - 1)
        .await?
        .into_iter()
        .map(|row| NodeResponse::new(row, current_version, now))
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

pub(super) async fn get(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
) -> ApiResult<Json<NodeResponse>> {
    let current_version = current_policy_version(&state.db).await?;
    let now = chrono::Utc::now().naive_utc();
    let row = node::Entity::find_by_id(node_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("node not found"))?;
    Ok(Json(NodeResponse::new(row, current_version, now)))
}
