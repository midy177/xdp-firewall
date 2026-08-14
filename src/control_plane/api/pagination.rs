use super::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};

const DEFAULT_PAGE_SIZE: u64 = 20;
const MAX_PAGE_SIZE: u64 = 500;

#[derive(Debug, Deserialize)]
pub(super) struct PaginationQuery {
    pub(super) page: Option<u64>,
    pub(super) page_size: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Pagination {
    pub(super) number: u64,
    pub(super) size: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct Page<T> {
    items: Vec<T>,
    total: u64,
    #[serde(rename = "page")]
    number: u64,
    #[serde(rename = "page_size")]
    size: u64,
    total_pages: u64,
}

impl PaginationQuery {
    pub(super) fn normalize(self) -> ApiResult<Pagination> {
        let page = self.page.unwrap_or(1);
        if page == 0 {
            return Err(ApiError::bad_request(
                "page must be greater than or equal to 1",
            ));
        }
        let page_size = self.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if page_size == 0 {
            return Err(ApiError::bad_request(
                "page_size must be greater than or equal to 1",
            ));
        }
        if page_size > MAX_PAGE_SIZE {
            return Err(ApiError::bad_request(format!(
                "page_size must be less than or equal to {MAX_PAGE_SIZE}"
            )));
        }
        Ok(Pagination {
            number: page,
            size: page_size,
        })
    }
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            number: 1,
            size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl<T> Page<T> {
    pub(super) fn new(items: Vec<T>, total: u64, pagination: Pagination) -> Self {
        Self {
            items,
            total,
            number: pagination.number,
            size: pagination.size,
            total_pages: total.div_ceil(pagination.size),
        }
    }
}
