use super::{
    source_fetch::{
        fetch_threat_source_prefixes, normalize_prefixes, parse_ipsum_line,
        parse_lenient_ipsum_line, parse_lenient_line_prefix, parse_prefix, parse_spamhaus_drop,
        threat_prefix_fingerprint, threat_redirect_policy,
    },
    *,
};
use crate::{
    db,
    db::entities::{threat_prefix, threat_source_state},
    policy::model::DEFAULT_POLICY_NAME,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};

#[test]
fn parses_ipsum_with_min_score() {
    assert!(parse_ipsum_line("1.1.1.1 2", 3).unwrap().is_none());
    let parsed = parse_ipsum_line("2.2.2.0/24 5", 3).unwrap().unwrap();
    assert_eq!(parsed.prefix, 24);
}

#[test]
fn builtin_sources_include_default_feeds() {
    assert_eq!(
        BUILTIN_THREAT_SOURCES
            .iter()
            .map(|source| source.name)
            .collect::<Vec<_>>(),
        ["ipsum", "spamhaus-drop", "voipbl"]
    );
    assert_eq!(BUILTIN_THREAT_SOURCES[0].min_score, Some(3));
    assert_eq!(BUILTIN_THREAT_SOURCES[1].format, "spamhaus_drop");
    assert_eq!(BUILTIN_THREAT_SOURCES[2].format, "voipbl");
    assert_eq!(BUILTIN_THREAT_SOURCES[2].url, "https://voipbl.org/update/");
}

#[test]
fn accepts_threat_url_credentials() {
    validate_source_url("https://user:secret@raw.githubusercontent.com/feed.txt").unwrap();
}

#[test]
fn accepts_http_threat_source_urls_without_host_restrictions() {
    validate_source_url("https://voipbl.org/update/").unwrap();
    validate_source_url(
        "https://operations-toolbox.oss-cn-hongkong.aliyuncs.com/threat-source/ban.txt",
    )
    .unwrap();
    validate_source_url("https://user:secret@raw.githubusercontent.com/feed.txt").unwrap();
}

#[test]
fn rejects_non_http_threat_source_urls() {
    let err = validate_source_url("file:///tmp/threat-source.txt").unwrap_err();
    assert!(err.to_string().contains("must use http or https"));
}

#[tokio::test]
async fn follows_307_threat_source_redirects() {
    use axum::{
        Router,
        http::{StatusCode, header},
        routing::get,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let location = format!("http://voipbl.org:{port}/feed");
    let app = Router::new()
        .route(
            "/start",
            get(move || async move {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, location)],
                )
            }),
        )
        .route("/feed", get(|| async { "198.51.100.0/24\n" }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::builder()
        .timeout(THREAT_HTTP_TIMEOUT)
        .redirect(threat_redirect_policy())
        .resolve("voipbl.org", SocketAddr::from(([127, 0, 0, 1], port)))
        .build()
        .unwrap();
    let prefixes = fetch_threat_source_prefixes(
        &client,
        &ThreatSource {
            name: "voipbl".to_string(),
            url: format!("http://voipbl.org:{port}/start"),
            format: ThreatFormat::Voipbl,
            min_score: Some(3),
        },
    )
    .await
    .unwrap();

    server.abort();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(
        prefixes[0],
        ThreatPrefix {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
            prefix: 24,
        }
    );
}

#[tokio::test]
async fn rejects_non_http_307_threat_source_redirects() {
    use axum::{
        Router,
        http::{StatusCode, header},
        routing::get,
    };

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/start",
        get(|| async {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "file:///tmp/threat-source.txt")],
            )
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::builder()
        .timeout(THREAT_HTTP_TIMEOUT)
        .redirect(threat_redirect_policy())
        .build()
        .unwrap();
    let err = fetch_threat_source_prefixes(
        &client,
        &ThreatSource {
            name: "test-feed".to_string(),
            url: format!("http://127.0.0.1:{port}/start"),
            format: ThreatFormat::Cidr,
            min_score: None,
        },
    )
    .await
    .unwrap_err();

    server.abort();
    assert!(err.to_string().contains("unsupported redirect"));
}

#[test]
fn parses_voipbl_cidr_lines() {
    let mut prefixes = Vec::new();
    for line in "# TOTAL NETBLOCK: 2\n\
             23.16.0.0/15\n\
             137.184.10/32\n\
             23.29.192.0/19\n"
        .lines()
    {
        if let Some(prefix) = parse_lenient_line_prefix(line, "voipbl") {
            prefixes.push(prefix);
        }
    }
    assert_eq!(prefixes.len(), 2);
    assert_eq!(prefixes[0].prefix, 15);
}

#[test]
fn lenient_line_formats_skip_invalid_cidrs() {
    assert!(parse_lenient_line_prefix("137.184.10/32", "cidr").is_none());
    assert!(parse_lenient_line_prefix("198.51.100.0/24", "cidr").is_some());
}

#[test]
fn lenient_ipsum_skips_invalid_scored_ip() {
    assert!(parse_lenient_ipsum_line("137.184.10 5", 3).is_none());
    assert!(parse_lenient_ipsum_line("198.51.100.1 5", 3).is_some());
}

#[test]
fn spamhaus_drop_skips_invalid_json_cidrs() {
    let prefixes = parse_spamhaus_drop(
        r#"[
                {"cidr":"137.184.10/32"},
                {"cidr":"198.51.100.0/24"}
            ]"#,
    )
    .unwrap();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(prefixes[0].prefix, 24);
}

#[test]
fn threat_prefix_fingerprint_changes_with_prefix_set() {
    let first = normalize_prefixes(vec![
        parse_prefix("203.0.113.10").unwrap(),
        parse_prefix("198.51.100.0/24").unwrap(),
    ]);
    let reordered = normalize_prefixes(vec![
        parse_prefix("198.51.100.0/24").unwrap(),
        parse_prefix("203.0.113.10").unwrap(),
    ]);
    let changed = normalize_prefixes(vec![
        parse_prefix("203.0.113.11").unwrap(),
        parse_prefix("198.51.100.0/24").unwrap(),
    ]);

    assert_eq!(
        threat_prefix_fingerprint(&first),
        threat_prefix_fingerprint(&reordered)
    );
    assert_ne!(
        threat_prefix_fingerprint(&first),
        threat_prefix_fingerprint(&changed)
    );
}

#[tokio::test]
async fn enabled_threat_source_states_missing_detects_enabled_source_without_state() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    assert!(!enabled_threat_source_states_missing(&db).await.unwrap());

    threat_source::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(true),
        name: Set("test-feed".to_string()),
        url: Set("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt".to_string()),
        format: Set("ipsum".to_string()),
        min_score: Set(Some(3)),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    assert!(enabled_threat_source_states_missing(&db).await.unwrap());

    threat_source_state::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set("test-feed".to_string()),
        fingerprint: Set("abc".to_string()),
        prefix_count: Set(1),
        last_checked_at: Set(chrono::Utc::now().naive_utc()),
        last_changed_at: Set(None),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    assert!(enabled_threat_source_states_missing(&db).await.unwrap());

    threat_prefix::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set("test-feed".to_string()),
        cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    assert!(!enabled_threat_source_states_missing(&db).await.unwrap());
}

#[tokio::test]
async fn unchanged_threat_refresh_preserves_state_and_prefix_updated_at() {
    use axum::{Router, routing::get};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route("/feed", get(|| async { "198.51.100.0/24\n" }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let now = chrono::Utc::now().naive_utc();

    threat_source::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        enabled: Set(true),
        name: Set("test-feed".to_string()),
        url: Set(format!("http://127.0.0.1:{port}/feed")),
        format: Set("cidr".to_string()),
        min_score: Set(None),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let first = refresh_enabled_threat_sources(&db).await.unwrap();
    assert_eq!(first.changed_source_count, 1);
    let first_state = load_threat_source_state(&db, "test-feed").await;
    let first_prefix = load_threat_prefix(&db, "test-feed").await;

    let second = refresh_until_not_running(&db).await;
    assert_eq!(second.changed_source_count, 0);
    assert!(!second.refreshed);
    let second_state = load_threat_source_state(&db, "test-feed").await;
    let second_prefix = load_threat_prefix(&db, "test-feed").await;

    server.abort();
    assert!(second_state.last_checked_at >= first_state.last_checked_at);
    assert_eq!(second_state.last_changed_at, first_state.last_changed_at);
    assert_eq!(second_state.updated_at, first_state.updated_at);
    assert_eq!(second_prefix.updated_at, first_prefix.updated_at);
}

#[tokio::test]
async fn threat_refresh_lock_preserves_updated_at() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();

    let guard = lock::ThreatRefreshDbLock::try_acquire(&db)
        .await
        .unwrap()
        .unwrap();
    let acquired = load_threat_refresh_lock_state(&db).await;
    drop(guard);
    let released = wait_for_threat_refresh_lock_idle(&db).await;

    assert_eq!(released.updated_at, acquired.updated_at);
}

#[tokio::test]
async fn threat_intel_lookup_rebuilds_from_persisted_prefixes() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let now = chrono::Utc::now().naive_utc();

    for name in ["feed-a", "feed-b"] {
        threat_source::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(true),
            name: Set(name.to_string()),
            url: Set(format!("https://example.com/{name}.txt")),
            format: Set("cidr".to_string()),
            min_score: Set(None),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
    }
    threat_prefix::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set("feed-a".to_string()),
        cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    threat_prefix::ActiveModel {
        policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
        source_name: Set("feed-b".to_string()),
        cidrs_json: Set(r#"["198.51.100.0/24"]"#.to_string()),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    let version = db::next_policy_version(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();

    let lookup = ThreatIntelLookup::default();
    lookup.rebuild_from_db(&db, version).await.unwrap();
    assert_eq!(
        lookup
            .lookup_source(&db, "198.51.100.10".parse().unwrap())
            .await,
        Some("feed-a,feed-b".to_string())
    );
    assert_eq!(
        lookup
            .lookup_source(&db, "203.0.113.10".parse().unwrap())
            .await,
        None
    );
}

async fn refresh_until_not_running(db: &DatabaseConnection) -> ThreatRefreshReport {
    for _ in 0..20 {
        let report = refresh_enabled_threat_sources(db).await.unwrap();
        if !report.running {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("threat refresh lock did not release");
}

async fn load_threat_source_state(
    db: &DatabaseConnection,
    source_name: &str,
) -> threat_source_state::Model {
    threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_source_state::Column::SourceName.eq(source_name))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

async fn load_threat_prefix(db: &DatabaseConnection, source_name: &str) -> threat_prefix::Model {
    threat_prefix::Entity::find()
        .filter(threat_prefix::Column::PolicyName.eq(DEFAULT_POLICY_NAME))
        .filter(threat_prefix::Column::SourceName.eq(source_name))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

async fn load_threat_refresh_lock_state(db: &DatabaseConnection) -> threat_source_state::Model {
    threat_source_state::Entity::find()
        .filter(threat_source_state::Column::PolicyName.eq("__threat_refresh_lock__"))
        .filter(threat_source_state::Column::SourceName.eq(DEFAULT_POLICY_NAME))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

async fn wait_for_threat_refresh_lock_idle(db: &DatabaseConnection) -> threat_source_state::Model {
    for _ in 0..20 {
        let row = load_threat_refresh_lock_state(db).await;
        if row.fingerprint == "idle" {
            return row;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("threat refresh lock did not release");
}

#[tokio::test]
async fn threat_intel_lookup_ignores_disabled_sources() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::db::migrate(&db).await.unwrap();
    let now = chrono::Utc::now().naive_utc();

    for (name, enabled) in [("enabled-feed", true), ("disabled-feed", false)] {
        threat_source::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(enabled),
            name: Set(name.to_string()),
            url: Set(format!("https://example.com/{name}.txt")),
            format: Set("cidr".to_string()),
            min_score: Set(None),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        threat_prefix::ActiveModel {
            policy_name: Set(DEFAULT_POLICY_NAME.to_string()),
            source_name: Set(name.to_string()),
            cidrs_json: Set(if enabled {
                r#"["198.51.100.0/24"]"#.to_string()
            } else {
                r#"["203.0.113.0/24"]"#.to_string()
            }),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
    }

    let lookup = ThreatIntelLookup::default();
    let version = db::next_policy_version(&db, DEFAULT_POLICY_NAME)
        .await
        .unwrap();
    lookup.rebuild_from_db(&db, version).await.unwrap();
    assert_eq!(
        lookup
            .lookup_source(&db, "198.51.100.10".parse().unwrap())
            .await,
        Some("enabled-feed".to_string())
    );
    assert_eq!(
        lookup
            .lookup_source(&db, "203.0.113.10".parse().unwrap())
            .await,
        None
    );
}
