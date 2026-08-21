use crate::db::sql::raw_sql;
use anyhow::Result;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend};

/// Free-form and blob-ish columns whose entity models declare
/// `column_type = "Text"`. `create_table_from_entity` maps that to MySQL
/// `TEXT` (64 KiB), which the aggregated CIDR JSON of large countries and
/// threat feeds exceeds, and pre-existing deployments may still carry
/// `varchar(255)` from before the annotation. Promote them explicitly on
/// MySQL; PostgreSQL and SQLite `TEXT` are effectively unlimited and are left
/// alone.
///
/// `(table, column, promoted type, NOT NULL)`
const MYSQL_TEXT_PROMOTIONS: &[(&str, &str, &str, bool)] = &[
    ("firewall_geo_ip_prefixes", "cidrs_json", "MEDIUMTEXT", true),
    ("firewall_threat_prefixes", "cidrs_json", "MEDIUMTEXT", true),
    ("firewall_nodes", "error", "TEXT", false),
    ("firewall_nodes", "interface_ips", "TEXT", true),
    ("firewall_rules", "comment", "TEXT", false),
    ("firewall_dynamic_rate_limits", "comment", "TEXT", false),
    ("firewall_temp_bans", "comment", "TEXT", false),
    ("firewall_trusted_cidrs", "comment", "TEXT", false),
];

pub(in crate::db::migrations) async fn ensure_mysql_text_capacity(
    db: &DatabaseConnection,
) -> Result<()> {
    if db.get_database_backend() != DbBackend::MySql {
        return Ok(());
    }
    for (table, column, promoted, not_null) in MYSQL_TEXT_PROMOTIONS {
        let Some(current) = mysql_column_type(db, table, column).await? else {
            continue;
        };
        if !needs_promotion(&current, promoted) {
            continue;
        }
        let nullability = if *not_null { "NOT NULL" } else { "NULL" };
        db.execute_raw(raw_sql(
            DbBackend::MySql,
            format!("ALTER TABLE {table} MODIFY {column} {promoted} {nullability}"),
        ))
        .await?;
    }
    Ok(())
}

/// Promote only when the current type cannot hold the data: a column that is
/// already at or above the target (e.g. manually widened to LONGTEXT) is left
/// untouched, so migrations never shrink or rewrite healthy columns. Unknown
/// types are also left alone.
fn needs_promotion(current: &str, promoted: &str) -> bool {
    let rank = |ty: &str| match ty.to_ascii_lowercase().as_str() {
        "varchar" | "char" => 0,
        "text" => 1,
        "mediumtext" => 2,
        "longtext" => 3,
        _ => usize::MAX,
    };
    rank(current) < rank(promoted)
}

async fn mysql_column_type(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> Result<Option<String>> {
    let row = db
        .query_one_raw(raw_sql(
            DbBackend::MySql,
            format!(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = database() AND table_name = '{table}' AND column_name = '{column}'"
            ),
        ))
        .await?;
    match row {
        // Read by index: MySQL 8's information_schema reports the column label
        // upper-cased ("DATA_TYPE") regardless of the query's casing.
        Some(row) => Ok(Some(row.try_get_by::<String, usize>(0)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::needs_promotion;

    #[test]
    fn needs_promotion_only_widens() {
        // Insufficient types are promoted.
        assert!(needs_promotion("varchar", "TEXT"));
        assert!(needs_promotion("text", "mediumtext"));
        assert!(needs_promotion("VARCHAR", "text"));
        // Equal capacity is a no-op.
        assert!(!needs_promotion("text", "text"));
        assert!(!needs_promotion("mediumtext", "mediumtext"));
        // Already-wider columns are never demoted or rewritten.
        assert!(!needs_promotion("mediumtext", "text"));
        assert!(!needs_promotion("longtext", "mediumtext"));
        // Unknown types are left alone.
        assert!(!needs_promotion("blob", "text"));
        assert!(!needs_promotion("json", "mediumtext"));
    }
}
