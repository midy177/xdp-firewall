use crate::db::entities::trusted_cidr;
use anyhow::{Context, Result};
use ipnet::IpNet;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, TransactionTrait};
use std::collections::HashSet;
use tracing::info;

mod reconcile;

use reconcile::{insert_missing_trusted_cidrs, reconcile_existing_trusted_cidrs};

pub async fn ensure_configured_trusted_cidrs(
    db: &DatabaseConnection,
    policy: &str,
    values: &[String],
) -> Result<()> {
    let cidrs = normalize_trusted_cidrs(values)?;
    let explicitly_configured =
        !values.is_empty() || std::env::var_os("XDP_FIREWALL_TRUSTED_CIDRS").is_some();
    if cidrs.is_empty() && !explicitly_configured {
        return Ok(());
    }

    let now = chrono::Utc::now().naive_utc();
    let mut changed = 0_u64;
    let desired = cidrs.iter().cloned().collect::<HashSet<_>>();
    let txn = db.begin().await?;
    let existing_rows = trusted_cidr::Entity::find()
        .filter(trusted_cidr::Column::PolicyName.eq(policy))
        .all(&txn)
        .await?;
    let existing_cidrs = existing_rows
        .iter()
        .map(|row| row.cidr.clone())
        .collect::<HashSet<_>>();

    changed += reconcile_existing_trusted_cidrs(&txn, existing_rows, &desired, now).await?;
    changed += insert_missing_trusted_cidrs(&txn, policy, cidrs, &existing_cidrs, now).await?;

    if changed > 0 {
        let version = crate::db::next_policy_version_in_transaction(&txn, policy).await?;
        txn.commit().await?;
        info!(
            policy,
            changed, version, "initialized trusted CIDRs from API CLI/env"
        );
    } else {
        txn.rollback().await?;
    }
    Ok(())
}

pub(super) fn normalize_trusted_cidrs(values: &[String]) -> Result<Vec<String>> {
    let mut cidrs = Vec::new();
    for value in values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let net = value
            .parse::<IpNet>()
            .with_context(|| format!("invalid trusted CIDR '{value}'"))?;
        let cidr = match net {
            IpNet::V4(net) => format!("{}/{}", net.network(), net.prefix_len()),
            IpNet::V6(net) => format!("{}/{}", net.network(), net.prefix_len()),
        };
        if !cidrs.contains(&cidr) {
            cidrs.push(cidr);
        }
    }
    Ok(cidrs)
}
