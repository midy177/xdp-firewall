use super::*;
use crate::db::entities::{geo_ip_list_state, geo_ip_prefix};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};

#[test]
fn parses_ipdeny_country_block_page_entries() {
    let body = r#"
        Zone files last updated: Thu 23 Jul 2026 12:10:16 PM CEST
        CHINA (CN) [download <a href="data/countries/cn.zone">cn.zone</a> ] Size: 133.84 KB (8805 IP blocks)
        [download <a href="data/aggregated/cn-aggregated.zone">cn-aggregrated.zone</a> ] (5507 IP blocks)
        CONGO, THE DEMOCRATIC REPUBLIC OF THE (CD) [download <a href="data/countries/cd.zone">cd.zone</a> ] Size: 1.32 KB (84 IP blocks)
        [download <a href="data/aggregated/cd-aggregated.zone">cd-aggregrated.zone</a> ] (83 IP blocks)
        <a href="Copyrights.txt">Copyrights.txt</a> 03-Dec-2019 03:45 3584
    "#;

    let entries = catalog::parse_ipdeny_index(body).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].country, "CN");
    assert_eq!(entries[0].name, "China");
    assert_eq!(
        entries[0].last_modified.as_deref(),
        Some("Thu 23 Jul 2026 12:10:16 PM CEST")
    );
    assert_eq!(entries[0].url, ipdeny_country_url("CN").unwrap());
    assert_eq!(entries[1].country, "CD");
    assert_eq!(entries[1].name, "Congo, The Democratic Republic Of The");
}

#[test]
fn geo_ip_list_changed_when_prefix_payload_is_missing() {
    let state = geo_ip_list_state::Model {
        id: 1,
        country: "US".to_string(),
        url: ipdeny_country_url("US").unwrap(),
        last_modified: Some("same".to_string()),
        etag: None,
        prefix_count: 1,
        last_checked_at: chrono::Utc::now().naive_utc(),
        last_downloaded_at: Some(chrono::Utc::now().naive_utc()),
        updated_at: chrono::Utc::now().naive_utc(),
    };
    assert!(geo_ip_list_changed(Some(&state), false, Some("same"), None));
    assert!(!geo_ip_list_changed(Some(&state), true, Some("same"), None));
}

#[test]
fn unchanged_country_catalog_entry_preserves_updated_at() {
    let updated_at = fixed_time(1_700_000_000);
    let now = fixed_time(1_700_000_100);
    let entry = catalog::IpdenyIndexEntry {
        country: "US".to_string(),
        name: "United States".to_string(),
        url: ipdeny_country_url("US").unwrap(),
        last_modified: Some("same".to_string()),
        size_bytes: Some(10),
    };
    let existing = geo_country_catalog::Model {
        id: 1,
        code: entry.country.clone(),
        name: entry.name.clone(),
        url: entry.url.clone(),
        last_modified: entry.last_modified.clone(),
        size_bytes: entry.size_bytes,
        last_checked_at: updated_at,
        updated_at,
    };

    assert_eq!(
        catalog::country_catalog_updated_at(Some(&existing), &entry, now),
        updated_at
    );
    let changed_entry = catalog::IpdenyIndexEntry {
        name: "United States Of America".to_string(),
        ..entry
    };
    assert_eq!(
        catalog::country_catalog_updated_at(Some(&existing), &changed_entry, now),
        now
    );
}

#[tokio::test]
async fn unchanged_geo_prefix_replacement_preserves_updated_at() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let updated_at = fixed_time(1_700_000_000);

    geo_ip_list_state::ActiveModel {
        country: Set("ZZ".to_string()),
        url: Set(ipdeny_country_url("ZZ").unwrap()),
        last_modified: Set(Some("old".to_string())),
        etag: Set(Some("old-etag".to_string())),
        prefix_count: Set(1),
        last_checked_at: Set(updated_at),
        last_downloaded_at: Set(Some(updated_at)),
        updated_at: Set(updated_at),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    geo_ip_prefix::ActiveModel {
        country: Set("ZZ".to_string()),
        cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
        updated_at: Set(updated_at),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let catalog = geo_country_catalog::Model {
        id: 1,
        code: "ZZ".to_string(),
        name: "Test Country".to_string(),
        url: ipdeny_country_url("ZZ").unwrap(),
        last_modified: Some("catalog".to_string()),
        size_bytes: None,
        last_checked_at: updated_at,
        updated_at,
    };
    let existing_state = state::load_geo_ip_list_state(&db, "ZZ").await.unwrap();
    let metadata = IpdenyMetadata {
        country: "ZZ".to_string(),
        url: ipdeny_country_url("ZZ").unwrap(),
        last_modified: Some("new".to_string()),
        etag: Some("new-etag".to_string()),
    };
    let prefixes = [GeoPrefix {
        addr: "198.51.100.0".parse().unwrap(),
        prefix: 24,
        country: encode_country("ZZ").unwrap(),
    }];

    assert!(
        !state::replace_geo_prefixes(&db, &catalog, existing_state.as_ref(), &metadata, &prefixes)
            .await
            .unwrap()
    );
    let state = load_geo_ip_list_state_row(&db, "ZZ").await;
    let prefix = load_geo_ip_prefix_row(&db, "ZZ").await;
    assert_eq!(state.updated_at, updated_at);
    assert_eq!(state.last_modified.as_deref(), Some("new"));
    assert_eq!(state.etag.as_deref(), Some("new-etag"));
    assert_eq!(prefix.updated_at, updated_at);
}

#[tokio::test]
async fn touched_geo_ip_list_state_preserves_updated_at() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let updated_at = fixed_time(1_700_000_000);

    geo_ip_list_state::ActiveModel {
        country: Set("US".to_string()),
        url: Set(ipdeny_country_url("US").unwrap()),
        last_modified: Set(Some("old".to_string())),
        etag: Set(Some("old-etag".to_string())),
        prefix_count: Set(1),
        last_checked_at: Set(updated_at),
        last_downloaded_at: Set(Some(updated_at)),
        updated_at: Set(updated_at),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let existing = state::load_geo_ip_list_state(&db, "US").await.unwrap();
    let metadata = IpdenyMetadata {
        country: "US".to_string(),
        url: ipdeny_country_url("US").unwrap(),
        last_modified: Some("same".to_string()),
        etag: Some("same-etag".to_string()),
    };
    state::touch_existing_geo_ip_state(&db, existing, &metadata)
        .await
        .unwrap();

    let state = load_geo_ip_list_state_row(&db, "US").await;
    assert_eq!(state.updated_at, updated_at);
    assert_eq!(state.last_modified.as_deref(), Some("same"));
    assert_eq!(state.etag.as_deref(), Some("same-etag"));
    assert!(state.last_checked_at > updated_at);
}

#[tokio::test]
async fn geo_refresh_lock_preserves_updated_at() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    let guard = lock::GeoRefreshDbLock::try_acquire(&db)
        .await
        .unwrap()
        .unwrap();
    let acquired = load_geo_ip_list_state_row(&db, "__refresh_lock__").await;
    drop(guard);
    let released = wait_for_geo_refresh_lock_idle(&db).await;

    assert_eq!(released.updated_at, acquired.updated_at);
}

#[tokio::test]
async fn load_persisted_geo_prefix_page_paginates_without_empty_tail_page() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    for (country, cidrs_json) in [
        ("CN", r#"["198.51.100.0/24","198.51.101.0/24"]"#),
        ("US", r#"["203.0.113.0/24"]"#),
    ] {
        geo_ip_prefix::ActiveModel {
            country: Set(country.to_string()),
            cidrs_json: Set(cidrs_json.to_string()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
    }

    let countries = vec!["CN".to_string(), "US".to_string()];
    let page = load_persisted_geo_prefix_page(&db, &countries, None, 2)
        .await
        .unwrap();
    assert_eq!(page.prefixes.len(), 2);
    assert_eq!(geo_prefix_to_cidr(&page.prefixes[0]), "198.51.100.0/24");
    assert_eq!(geo_prefix_to_cidr(&page.prefixes[1]), "198.51.101.0/24");
    assert_eq!(page.next_page_token.as_deref(), Some("1:0"));

    let page = load_persisted_geo_prefix_page(&db, &countries, page.next_page_token.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(page.prefixes.len(), 1);
    assert_eq!(geo_prefix_to_cidr(&page.prefixes[0]), "203.0.113.0/24");
    assert_eq!(page.next_page_token, None);
}

fn fixed_time(seconds: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap()
        .naive_utc()
}

async fn load_geo_ip_list_state_row(
    db: &DatabaseConnection,
    country: &str,
) -> geo_ip_list_state::Model {
    geo_ip_list_state::Entity::find()
        .filter(geo_ip_list_state::Column::Country.eq(country))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

async fn load_geo_ip_prefix_row(db: &DatabaseConnection, country: &str) -> geo_ip_prefix::Model {
    geo_ip_prefix::Entity::find()
        .filter(geo_ip_prefix::Column::Country.eq(country))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

async fn wait_for_geo_refresh_lock_idle(db: &DatabaseConnection) -> geo_ip_list_state::Model {
    for _ in 0..20 {
        let row = load_geo_ip_list_state_row(db, "__refresh_lock__").await;
        if row.last_modified.as_deref() == Some("idle") {
            return row;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("GeoIP refresh lock did not release");
}

#[tokio::test]
async fn load_persisted_geo_prefix_page_splits_within_a_single_country() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    geo_ip_prefix::ActiveModel {
        country: Set("CN".to_string()),
        cidrs_json: Set(r#"["198.51.100.0/24","198.51.101.0/24","198.51.102.0/24"]"#.to_string()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let countries = vec!["CN".to_string()];
    let page = load_persisted_geo_prefix_page(&db, &countries, None, 2)
        .await
        .unwrap();
    assert_eq!(page.prefixes.len(), 2);
    assert_eq!(geo_prefix_to_cidr(&page.prefixes[0]), "198.51.100.0/24");
    assert_eq!(geo_prefix_to_cidr(&page.prefixes[1]), "198.51.101.0/24");
    assert_eq!(page.next_page_token.as_deref(), Some("0:2"));

    let page = load_persisted_geo_prefix_page(&db, &countries, page.next_page_token.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(page.prefixes.len(), 1);
    assert_eq!(geo_prefix_to_cidr(&page.prefixes[0]), "198.51.102.0/24");
    assert_eq!(page.next_page_token, None);
}

#[tokio::test]
async fn geoip_lookup_rebuilds_from_persisted_prefixes() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    geo_country_catalog::ActiveModel {
        code: Set("ZZ".to_string()),
        name: Set("Test Country".to_string()),
        url: Set(ipdeny_country_url("ZZ").unwrap()),
        last_modified: Set(Some("test".to_string())),
        size_bytes: Set(None),
        last_checked_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    geo_ip_prefix::ActiveModel {
        country: Set("ZZ".to_string()),
        cidrs_json: Set(r#"["203.0.113.0/24"]"#.to_string()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let lookup = GeoIpLookup::default();
    assert_eq!(lookup.rebuild_from_db(&db).await.unwrap(), 1);
    assert_eq!(
        lookup.lookup_country("203.0.113.10".parse().unwrap()),
        Some("ZZ".to_string())
    );
    assert_eq!(
        lookup.lookup_country_record("203.0.113.10".parse().unwrap()),
        Some(GeoIpCountry {
            code: "ZZ".to_string(),
            name: Some("Test Country".to_string())
        })
    );
    assert_eq!(
        lookup.lookup_country("198.51.100.10".parse().unwrap()),
        None
    );
}

#[tokio::test]
async fn geoip_lookup_skips_ipv6_prefixes_for_ipdeny_ipv4_database() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    geo_country_catalog::ActiveModel {
        code: Set("ZZ".to_string()),
        name: Set("Test Country".to_string()),
        url: Set(ipdeny_country_url("ZZ").unwrap()),
        last_modified: Set(Some("test".to_string())),
        size_bytes: Set(None),
        last_checked_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    geo_ip_prefix::ActiveModel {
        country: Set("ZZ".to_string()),
        cidrs_json: Set(r#"["2001:db8::/32","203.0.113.0/24"]"#.to_string()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let lookup = GeoIpLookup::default();
    assert_eq!(lookup.rebuild_from_db(&db).await.unwrap(), 1);
    assert_eq!(
        lookup.lookup_country("203.0.113.10".parse().unwrap()),
        Some("ZZ".to_string())
    );
    assert_eq!(lookup.lookup_country("2001:db8::1".parse().unwrap()), None);
}
