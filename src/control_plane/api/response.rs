use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(super) struct HealthResponse {
    pub(super) status: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct Versioned<T> {
    pub(super) version: i64,
    pub(super) data: T,
}

#[derive(Debug, Deserialize)]
pub(super) struct BatchRequest<T> {
    pub(super) items: Vec<T>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BatchDeleteRequest {
    pub(super) ids: Vec<i32>,
}

#[derive(Debug, Serialize)]
pub(super) struct BatchDeleteResponse {
    pub(super) deleted: u64,
}

pub(super) struct CreateRows<T> {
    pub(super) rows: Vec<T>,
    pub(super) inserted: bool,
    pub(super) active_changed: bool,
}

impl<T> CreateRows<T> {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            rows: Vec::with_capacity(capacity),
            inserted: false,
            active_changed: false,
        }
    }

    pub(super) fn push(&mut self, row: T, inserted: bool, active_changed: bool) {
        self.rows.push(row);
        self.inserted |= inserted;
        self.active_changed |= active_changed;
    }
}

pub(super) fn created_status(inserted: bool) -> StatusCode {
    if inserted {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    }
}
