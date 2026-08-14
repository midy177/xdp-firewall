use sea_orm::{DbBackend, Statement};

#[must_use]
pub fn placeholder(backend: DbBackend, n: usize) -> String {
    match backend {
        DbBackend::Postgres => format!("${n}"),
        _ => "?".to_string(),
    }
}

pub fn raw_sql(backend: DbBackend, sql: impl Into<String>) -> Statement {
    Statement::from_string(backend, sql.into())
}
