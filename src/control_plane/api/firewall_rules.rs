use super::{ApiResult, ApiState, pagination::Page};
use crate::db::entities::firewall_rule;
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
use query::RuleQuery;

pub(super) async fn list(
    State(state): State<ApiState>,
    Query(query): Query<RuleQuery>,
) -> ApiResult<Json<Page<firewall_rule::Model>>> {
    let pagination = query.pagination().normalize()?;
    let paginator = query
        .apply_filters(firewall_rule::Entity::find())?
        .order_by_asc(firewall_rule::Column::Priority)
        .paginate(&state.db, pagination.size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.number - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}
