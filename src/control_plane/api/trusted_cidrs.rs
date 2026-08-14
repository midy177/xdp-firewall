use super::{
    ApiResult, ApiState,
    pagination::{Page, PaginationQuery},
};
use crate::db::entities::trusted_cidr;
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
pub(super) use delete::{delete_batch, delete_by_id, delete_by_query};
use query::TrustedCidrQuery;

pub(super) async fn list(
    State(state): State<ApiState>,
    Query(query): Query<TrustedCidrQuery>,
) -> ApiResult<Json<Page<trusted_cidr::Model>>> {
    let pagination = PaginationQuery {
        page: query.page,
        page_size: query.page_size,
    }
    .normalize()?;
    let paginator = query
        .apply_filters(trusted_cidr::Entity::find())?
        .order_by_asc(trusted_cidr::Column::Cidr)
        .paginate(&state.db, pagination.size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.number - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}
