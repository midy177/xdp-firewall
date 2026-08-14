use super::super::{
    ThreatPrefix, ThreatSource,
    source_fetch::{fetch_threat_source_prefixes, normalize_prefixes, threat_prefix_fingerprint},
};
use crate::{db::entities::threat_source_state, policy::model::DEFAULT_POLICY_NAME};
use anyhow::{Context, Result};
use sea_orm::Set;
use std::collections::{HashMap, HashSet};

pub(super) struct ThreatRefreshBatch {
    pub(super) states: Vec<threat_source_state::ActiveModel>,
    pub(super) changed_prefixes_by_source: Vec<(String, Vec<ThreatPrefix>)>,
    pub(super) changed_source_count: u64,
    pub(super) prefix_count: usize,
    pub(super) checked_at: chrono::NaiveDateTime,
}

pub(super) async fn refresh_threat_source_batch(
    client: &reqwest::Client,
    sources: &[ThreatSource],
    existing: &HashMap<String, threat_source_state::Model>,
    existing_prefix_sources: &HashSet<String>,
    now: chrono::NaiveDateTime,
) -> Result<ThreatRefreshBatch> {
    let mut batch = ThreatRefreshBatch {
        states: Vec::with_capacity(sources.len()),
        changed_prefixes_by_source: Vec::with_capacity(sources.len()),
        changed_source_count: 0,
        prefix_count: 0,
        checked_at: now,
    };
    for source in sources {
        refresh_one_source(
            client,
            source,
            existing,
            existing_prefix_sources,
            now,
            &mut batch,
        )
        .await?;
    }
    Ok(batch)
}

async fn refresh_one_source(
    client: &reqwest::Client,
    source: &ThreatSource,
    existing: &HashMap<String, threat_source_state::Model>,
    existing_prefix_sources: &HashSet<String>,
    now: chrono::NaiveDateTime,
    batch: &mut ThreatRefreshBatch,
) -> Result<()> {
    let (prefixes, fingerprint) = fetch_normalized_source_prefixes(client, source).await?;
    let prefix_count = prefixes.len();
    batch.prefix_count += prefix_count;
    let changed = threat_source_changed(source, &fingerprint, existing, existing_prefix_sources);
    if changed {
        batch.changed_source_count += 1;
        batch
            .changed_prefixes_by_source
            .push((source.name.clone(), prefixes));
    }
    batch.states.push(threat_source_refresh_state(
        source,
        fingerprint,
        prefix_count,
        changed,
        existing,
        now,
    )?);
    Ok(())
}

async fn fetch_normalized_source_prefixes(
    client: &reqwest::Client,
    source: &ThreatSource,
) -> Result<(Vec<ThreatPrefix>, String)> {
    let prefixes = normalize_prefixes(fetch_threat_source_prefixes(client, source).await?);
    let fingerprint = threat_prefix_fingerprint(&prefixes);
    Ok((prefixes, fingerprint))
}

fn threat_source_changed(
    source: &ThreatSource,
    fingerprint: &str,
    existing: &HashMap<String, threat_source_state::Model>,
    existing_prefix_sources: &HashSet<String>,
) -> bool {
    existing
        .get(&source.name)
        .is_none_or(|state| state.fingerprint != fingerprint)
        || !existing_prefix_sources.contains(&source.name)
}

fn threat_source_refresh_state(
    source: &ThreatSource,
    fingerprint: String,
    prefix_count: usize,
    changed: bool,
    existing: &HashMap<String, threat_source_state::Model>,
    now: chrono::NaiveDateTime,
) -> Result<threat_source_state::ActiveModel> {
    Ok(threat_source_state::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set(source.name.clone()),
        fingerprint: Set(fingerprint),
        prefix_count: Set(prefix_count
            .try_into()
            .context("threat prefix count overflowed")?),
        last_checked_at: Set(now),
        last_changed_at: Set(if changed {
            Some(now)
        } else {
            existing
                .get(&source.name)
                .and_then(|state| state.last_changed_at)
        }),
        updated_at: Set(threat_source_updated_at(source, changed, existing, now)),
        ..Default::default()
    })
}

fn threat_source_updated_at(
    source: &ThreatSource,
    changed: bool,
    existing: &HashMap<String, threat_source_state::Model>,
    now: chrono::NaiveDateTime,
) -> chrono::NaiveDateTime {
    if changed {
        return now;
    }
    existing
        .get(&source.name)
        .map_or(now, |state| state.updated_at)
}
