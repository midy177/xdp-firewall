use super::{
    ApiResult, ApiState,
    pagination::{Page, PaginationQuery},
};
use crate::db::entities::threat_source;
use axum::{
    Json,
    extract::{Query, State},
};
use sea_orm::{EntityTrait, PaginatorTrait, QueryOrder};

mod create;
mod delete;
mod input;
mod query;
mod queued;
mod refresh_task;
mod update;

pub(super) use create::{create, create_batch};
pub(super) use delete::{delete_batch, delete_by_id, delete_by_query};
use query::ThreatSourceQuery;
pub(super) use queued::spawn_threat_refresh;
pub(super) use refresh_task::refresh;
pub(super) use update::update;

pub(super) async fn list(
    State(state): State<ApiState>,
    Query(query): Query<ThreatSourceQuery>,
) -> ApiResult<Json<Page<threat_source::Model>>> {
    let pagination = PaginationQuery {
        page: query.page,
        page_size: query.page_size,
    }
    .normalize()?;
    let paginator = query
        .apply_filters(threat_source::Entity::find())?
        .order_by_asc(threat_source::Column::Name)
        .paginate(&state.db, pagination.size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.number - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}
