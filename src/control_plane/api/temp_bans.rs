use super::{ApiResult, ApiState, pagination::Page};
use crate::db::entities::temp_ban;
use axum::{
    Json,
    extract::{Query, State},
};
use sea_orm::{EntityTrait, PaginatorTrait, QueryOrder};

mod create;
mod delete;
mod input;
mod query;

pub(super) use create::{create, create_batch};
pub(super) use delete::{delete_batch, delete_by_id};
use query::TempBanQuery;

pub(super) async fn list(
    State(state): State<ApiState>,
    Query(query): Query<TempBanQuery>,
) -> ApiResult<Json<Page<temp_ban::Model>>> {
    let pagination = query.pagination().normalize()?;
    let select = query.apply_filters(temp_ban::Entity::find())?;
    let paginator = select
        .order_by_asc(temp_ban::Column::ExpiresAt)
        .paginate(&state.db, pagination.size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.number - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}
