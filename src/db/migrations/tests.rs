use super::*;
use crate::db::{entities, raw_sql};
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Set,
};

#[tokio::test]
async fn migrate_backfills_and_requires_firewall_rule_key() {
    let db = sqlite_memory_db().await;
    let backend = DbBackend::Sqlite;

    create_legacy_firewall_rules_table(&db, backend).await;
    insert_legacy_firewall_rule(&db, backend).await;

    migrate(&db).await.unwrap();

    let rule_key = migrated_firewall_rule_key(&db, backend).await;
    assert_eq!(
        rule_key,
        entities::firewall_rule::generated_rule_key(
            10,
            "deny",
            "203.0.113.0/24",
            Some("tcp"),
            Some(443),
        )
    );
    assert_firewall_rule_key_constraints(&db, backend, &rule_key).await;
}

#[tokio::test]
async fn migrate_is_idempotent_across_restarts() {
    let db = sqlite_memory_db().await;

    migrate(&db).await.unwrap();
    // A second run must succeed too: startup replays the full migration set,
    // and index creation probes the catalog first instead of relying on
    // `CREATE INDEX IF NOT EXISTS`, which MySQL does not support.
    migrate(&db).await.unwrap();
}

async fn sqlite_memory_db() -> DatabaseConnection {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.max_connections(1);
    Database::connect(options).await.unwrap()
}

async fn create_legacy_firewall_rules_table(db: &DatabaseConnection, backend: DbBackend) {
    db.execute_raw(raw_sql(
        backend,
        "CREATE TABLE firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            policy_name TEXT NOT NULL,
            enabled BOOLEAN NOT NULL,
            priority INTEGER NOT NULL,
            action TEXT NOT NULL,
            cidr TEXT NOT NULL,
            protocol TEXT,
            port INTEGER,
            comment TEXT,
            updated_at TIMESTAMP NOT NULL
        )",
    ))
    .await
    .unwrap();
}

async fn insert_legacy_firewall_rule(db: &DatabaseConnection, backend: DbBackend) {
    db.execute_raw(raw_sql(
        backend,
        "INSERT INTO firewall_rules (
            policy_name,
            enabled,
            priority,
            action,
            cidr,
            protocol,
            port,
            comment,
            updated_at
        ) VALUES (
            'default',
            TRUE,
            10,
            'deny',
            '203.0.113.0/24',
            'tcp',
            443,
            NULL,
            '2026-01-01 00:00:00'
        )",
    ))
    .await
    .unwrap();
}

async fn migrated_firewall_rule_key(db: &DatabaseConnection, backend: DbBackend) -> String {
    let row = db
        .query_one_raw(raw_sql(
            backend,
            "SELECT rule_key FROM firewall_rules WHERE id = 1",
        ))
        .await
        .unwrap()
        .unwrap();
    row.try_get::<String>("", "rule_key").unwrap()
}

async fn assert_firewall_rule_key_constraints(
    db: &DatabaseConnection,
    backend: DbBackend,
    rule_key: &str,
) {
    assert_firewall_rule_key_is_required(db).await;
    assert_firewall_rule_key_rejects_null(db, backend).await;
    assert_firewall_rule_key_rejects_duplicates(db, backend, rule_key).await;
}

async fn assert_firewall_rule_key_is_required(db: &DatabaseConnection) {
    assert!(
        legacy::sqlite_column_is_not_null(db, "firewall_rules", "rule_key")
            .await
            .unwrap()
    );
}

async fn assert_firewall_rule_key_rejects_null(db: &DatabaseConnection, backend: DbBackend) {
    let insert_null = db
        .execute_raw(raw_sql(
            backend,
            "INSERT INTO firewall_rules (
                policy_name,
                rule_key,
                enabled,
                priority,
                action,
                cidr,
                protocol,
                port,
                comment,
                updated_at
            ) VALUES (
                'default',
                NULL,
                TRUE,
                20,
                'allow',
                '198.51.100.0/24',
                'udp',
                53,
                NULL,
                '2026-01-01 00:00:00'
            )",
        ))
        .await;
    assert!(insert_null.is_err());
}

async fn assert_firewall_rule_key_rejects_duplicates(
    db: &DatabaseConnection,
    backend: DbBackend,
    rule_key: &str,
) {
    let insert_duplicate_rule_key = db
        .execute_raw(raw_sql(
            backend,
            format!(
                "INSERT INTO firewall_rules (
                    policy_name,
                    rule_key,
                    enabled,
                    priority,
                    action,
                    cidr,
                    protocol,
                    port,
                    comment,
                    updated_at
                ) VALUES (
                    'secondary',
                    '{rule_key}',
                    TRUE,
                    20,
                    'allow',
                    '198.51.100.0/24',
                    'udp',
                    53,
                    NULL,
                    '2026-01-01 00:00:00'
                )"
            ),
        ))
        .await;
    assert!(insert_duplicate_rule_key.is_err());
}

#[tokio::test]
async fn migrate_backfills_temp_ban_cidr_and_drops_legacy_ip_column() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.max_connections(1);
    let db = Database::connect(options).await.unwrap();
    let backend = DbBackend::Sqlite;

    create_legacy_temp_bans_table(&db, backend).await;
    insert_legacy_temp_ban(&db, backend).await;
    migrate(&db).await.unwrap();
    assert_legacy_temp_ban_ip_migrated_to_cidr(&db, backend).await;

    entities::temp_ban::ActiveModel {
        policy_name: Set("edge".to_string()),
        cidr: Set("203.0.113.11/32".to_string()),
        protocol: Set("any".to_string()),
        port: Set(None),
        expires_at: Set(chrono::Utc::now().naive_utc()),
        comment: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
}

async fn create_legacy_temp_bans_table(db: &DatabaseConnection, backend: DbBackend) {
    db.execute_raw(raw_sql(
        backend,
        "CREATE TABLE firewall_temp_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            policy_name TEXT NOT NULL,
            ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER,
            expires_at TIMESTAMP NOT NULL,
            comment TEXT,
            created_at TIMESTAMP NOT NULL
        )",
    ))
    .await
    .unwrap();
}

async fn insert_legacy_temp_ban(db: &DatabaseConnection, backend: DbBackend) {
    db.execute_raw(raw_sql(
        backend,
        "INSERT INTO firewall_temp_bans (
            policy_name,
            ip,
            protocol,
            port,
            expires_at,
            comment,
            created_at
        ) VALUES (
            'edge',
            '203.0.113.10',
            'any',
            NULL,
            '2026-01-01 00:05:00',
            NULL,
            '2026-01-01 00:00:00'
        )",
    ))
    .await
    .unwrap();
}

async fn assert_legacy_temp_ban_ip_migrated_to_cidr(db: &DatabaseConnection, backend: DbBackend) {
    assert!(
        !legacy::column_exists(db, "firewall_temp_bans", "ip")
            .await
            .unwrap()
    );
    let row = db
        .query_one_raw(raw_sql(
            backend,
            "SELECT cidr FROM firewall_temp_bans WHERE id = 1",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.try_get::<String>("", "cidr").unwrap(),
        "203.0.113.10/32"
    );
}

#[tokio::test]
async fn migrate_adds_node_interface_ips_column() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.max_connections(1);
    let db = Database::connect(options).await.unwrap();
    let backend = DbBackend::Sqlite;

    db.execute_raw(raw_sql(
        backend,
        "CREATE TABLE firewall_nodes (
            node_id TEXT PRIMARY KEY NOT NULL,
            policy_name TEXT NOT NULL,
            interface_name TEXT NOT NULL,
            last_seen_at TIMESTAMP NOT NULL,
            last_applied_version BIGINT NOT NULL,
            status TEXT NOT NULL,
            error TEXT
        )",
    ))
    .await
    .unwrap();
    db.execute_raw(raw_sql(
        backend,
        "INSERT INTO firewall_nodes (
            node_id,
            policy_name,
            interface_name,
            last_seen_at,
            last_applied_version,
            status,
            error
        ) VALUES (
            'node-a',
            'default',
            'eth0',
            '2026-01-01 00:00:00',
            1,
            'ok',
            NULL
        )",
    ))
    .await
    .unwrap();

    migrate(&db).await.unwrap();

    assert!(
        legacy::column_exists(&db, "firewall_nodes", "interface_ips")
            .await
            .unwrap()
    );
    let row = db
        .query_one_raw(raw_sql(
            backend,
            "SELECT interface_ips FROM firewall_nodes WHERE node_id = 'node-a'",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "interface_ips").unwrap(), "");
}
