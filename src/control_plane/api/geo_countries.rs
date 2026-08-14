use super::{
    ApiResult, ApiState, BatchRequest, CreateRows, Versioned, bump_policy_version_if_active,
    created_status,
    pagination::{Page, PaginationQuery},
    policy_version_after_optional_bump, validate_batch_len,
};
use crate::db::entities::geo_country_policy;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use sea_orm::{EntityTrait, PaginatorTrait, QueryOrder, TransactionTrait};

mod delete;
mod input;
mod lookup;
mod query;
mod refresh_task;

pub(super) use delete::{delete_batch, delete_by_id, delete_by_query};
use input::{CreateGeoCountryRequest, create_geo_country, geo_country_input};
pub(super) use lookup::lookup;
use query::GeoCountryQuery;
pub(super) use refresh_task::refresh;

pub(super) async fn list(
    State(state): State<ApiState>,
    Query(query): Query<GeoCountryQuery>,
) -> ApiResult<Json<Page<geo_country_policy::Model>>> {
    let pagination = PaginationQuery {
        page: query.page,
        page_size: query.page_size,
    }
    .normalize()?;
    let paginator = query
        .apply_filters(geo_country_policy::Entity::find())?
        .order_by_asc(geo_country_policy::Column::Country)
        .paginate(&state.db, pagination.size);
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.number - 1).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

pub(super) async fn create(
    State(state): State<ApiState>,
    Json(request): Json<CreateGeoCountryRequest>,
) -> ApiResult<(StatusCode, Json<Versioned<geo_country_policy::Model>>)> {
    let txn = state.db.begin().await?;
    let created = create_geo_country(&txn, geo_country_input(&request)?).await?;
    let bumped_version =
        bump_policy_version_if_active(&txn, created.inserted && created.row.enabled).await?;
    txn.commit().await?;
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    Ok((
        created_status(created.inserted),
        Json(Versioned {
            version,
            data: created.row,
        }),
    ))
}

pub(super) async fn create_batch(
    State(state): State<ApiState>,
    Json(request): Json<BatchRequest<CreateGeoCountryRequest>>,
) -> ApiResult<(StatusCode, Json<Versioned<Vec<geo_country_policy::Model>>>)> {
    validate_batch_len(request.items.len())?;
    let inputs = request
        .items
        .into_iter()
        .map(|request| geo_country_input(&request))
        .collect::<ApiResult<Vec<_>>>()?;
    let txn = state.db.begin().await?;
    let mut summary = CreateRows::with_capacity(inputs.len());
    for input in inputs {
        let created = create_geo_country(&txn, input).await?;
        let active_changed = created.inserted && created.row.enabled;
        summary.push(created.row, created.inserted, active_changed);
    }
    let bumped_version = bump_policy_version_if_active(&txn, summary.active_changed).await?;
    txn.commit().await?;
    let version = policy_version_after_optional_bump(&state.db, bumped_version).await?;
    Ok((
        created_status(summary.inserted),
        Json(Versioned {
            version,
            data: summary.rows,
        }),
    ))
}
