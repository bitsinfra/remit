use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, StringArray, TimestampMillisecondArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use remit_wire::ParamType;
use serde_json::{json, Map, Value};

use crate::*;

fn ms(s: &str) -> i64 {
    remit_types::parse_timestamp_ms(s).unwrap()
}

fn plane() -> ReadPlane {
    let mut store = Store::new();
    let ts = DataType::Timestamp(TimeUnit::Millisecond, None);
    let schema = Arc::new(Schema::new(vec![
        Field::new("start_at", ts.clone(), false),
        Field::new("end_at", ts, false),
        Field::new("status", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
    ]));
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(TimestampMillisecondArray::from(vec![
                ms("2026-11-24T10:00:00Z"),
                ms("2026-11-25T13:00:00Z"),
                ms("2026-12-20T09:00:00Z"),
                ms("2026-11-26T09:00:00Z"),
            ])),
            Arc::new(TimestampMillisecondArray::from(vec![
                ms("2026-11-24T11:00:00Z"),
                ms("2026-11-25T14:30:00Z"),
                ms("2026-12-20T10:00:00Z"),
                ms("2026-11-26T10:00:00Z"),
            ])),
            Arc::new(StringArray::from(vec![
                "confirmed",
                "confirmed",
                "confirmed",
                "cancelled",
            ])),
            Arc::new(StringArray::from(vec![
                "Dentist",
                "1:1 with Bob",
                "Flight",
                "Old",
            ])),
        ],
    )
    .unwrap();
    store.insert_batches("calendar.events", schema, vec![b]);

    let schema = Arc::new(Schema::new(vec![
        Field::new("account_id", DataType::Utf8, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("arr", DataType::Float64, false),
        Field::new("owner", DataType::Utf8, false),
        Field::new("email", DataType::Utf8, false),
    ]));
    let regions = [
        "EMEA", "EMEA", "EMEA", "AMER", "AMER", "AMER", "AMER", "APAC",
    ];
    let n = regions.len();
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                (0..n).map(|i| format!("a{i}")).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(regions.to_vec())),
            Arc::new(Float64Array::from(
                (0..n).map(|i| 1000.0 * (i + 1) as f64).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                (0..n)
                    .map(|i| {
                        if i % 2 == 0 {
                            "did:web:bob"
                        } else {
                            "did:web:eve"
                        }
                    })
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                (0..n).map(|i| format!("u{i}@x.com")).collect::<Vec<_>>(),
            )),
        ],
    )
    .unwrap();
    store.insert_batches("crm.accounts", schema.clone(), vec![b.clone()]);
    store.insert_batches("crm.mine", schema, vec![b]);
    store.insert_batches(
        "hr.salaries",
        Arc::new(Schema::new(vec![Field::new("x", DataType::Utf8, false)])),
        vec![RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("x", DataType::Utf8, false)])),
            vec![Arc::new(StringArray::from(vec!["secret"]))],
        )
        .unwrap()],
    );

    let mut res = BTreeMap::new();
    let mut cal = ResourceConfig::default();
    cal.columns.insert(
        "title".into(),
        ColumnConfig {
            expose: false,
            ..Default::default()
        },
    );
    res.insert("calendar.events".to_string(), cal);
    let mut crm = ResourceConfig {
        aggregate_only: true,
        k: Some(3),
        privacy_unit: Some("account_id".into()),
        ..Default::default()
    };
    crm.columns.insert(
        "email".into(),
        ColumnConfig {
            expose: true,
            mask: Some("hash".into()),
            ..Default::default()
        },
    );
    res.insert("crm.accounts".to_string(), crm);
    res.insert(
        "crm.mine".to_string(),
        ResourceConfig {
            owner_column: Some("owner".into()),
            ..Default::default()
        },
    );
    res.insert(
        "hr.salaries".to_string(),
        ResourceConfig {
            visible_to: vec!["hr-agents".into()],
            ..Default::default()
        },
    );
    ReadPlane::new(&store, &res, "salt").unwrap()
}

fn alice() -> Principal {
    Principal {
        id: "did:web:bob".into(),
        groups: vec!["verified-agents".into()],
    }
}

fn ptypes() -> BTreeMap<String, ParamType> {
    [
        ("from".to_string(), ParamType::Timestamp),
        ("until".to_string(), ParamType::Timestamp),
    ]
    .into_iter()
    .collect()
}

const BUSY: &str = "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'";

fn params() -> Map<String, Value> {
    json!({"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z"})
        .as_object()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn lineage_includes_filter_columns() {
    let p = plane();
    let f = p.analyze(BUSY, &alice(), &ptypes()).await.unwrap();
    let t = &f.tables["calendar.events"];
    assert_eq!(
        t.columns.iter().cloned().collect::<Vec<_>>(),
        vec!["end_at", "start_at", "status"]
    );
    assert!(!t.aggregated);
    assert!(!f.aggregate_only);
    assert_eq!(
        f.output,
        vec![
            ("start_at".to_string(), "timestamp".to_string()),
            ("end_at".to_string(), "timestamp".to_string())
        ]
    );
}

#[tokio::test]
async fn projected_subquery_predicates_fail_during_planning() {
    let p = plane();
    for sql in [
        "SELECT NOT EXISTS (SELECT 1 FROM calendar.events WHERE end_at > $from) AS free",
        "SELECT start_at IN (SELECT end_at FROM calendar.events) AS matches FROM calendar.events",
    ] {
        let e = p.analyze(sql, &alice(), &ptypes()).await.unwrap_err();
        assert_eq!(e.code(), "RMT-E0301");
        assert!(e.to_string().contains("SELECT expressions"), "{e}");
    }
    p.analyze(
        "SELECT COUNT(*) = 0 AS free FROM calendar.events WHERE end_at > $from",
        &alice(),
        &ptypes(),
    )
    .await
    .unwrap();
    p.analyze(
        "SELECT start_at FROM calendar.events WHERE EXISTS (SELECT 1 FROM calendar.events WHERE end_at > $from)",
        &alice(),
        &ptypes(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn hidden_columns_and_tables_do_not_exist() {
    let p = plane();
    let e = p
        .analyze(
            "SELECT title FROM calendar.events",
            &alice(),
            &BTreeMap::new(),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("title"), "{e}");
    assert!(!e.to_string().contains("__raw"), "{e}");
    let e = p
        .analyze("SELECT * FROM hr.salaries", &alice(), &BTreeMap::new())
        .await
        .unwrap_err();
    let e2 = p
        .analyze("SELECT * FROM hr.nonexistent", &alice(), &BTreeMap::new())
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string().replace("salaries", "X"),
        e2.to_string().replace("nonexistent", "X")
    );
    let hr = Principal {
        id: "did:web:hr".into(),
        groups: vec!["hr-agents".into()],
    };
    assert!(p
        .analyze("SELECT * FROM hr.salaries", &hr, &BTreeMap::new())
        .await
        .is_ok());
    // Wildcards only see exposed columns.
    let f = p
        .analyze("SELECT * FROM calendar.events", &alice(), &BTreeMap::new())
        .await
        .unwrap();
    assert!(!f.tables["calendar.events"].columns.contains("title"));
}

#[tokio::test]
async fn execute_with_params() {
    let p = plane();
    let c = ScanCounter::new(1000, 1 << 30);
    let out = p
        .execute(
            BUSY,
            &alice(),
            &params(),
            &ptypes(),
            &ReadLimits::default(),
            c.clone(),
        )
        .await
        .unwrap();
    let rows = arrowconv::batches_to_rows(&out.batches);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["start_at"], json!("2026-11-24T10:00:00Z"));
    assert_eq!(c.rows.load(std::sync::atomic::Ordering::Relaxed), 4);
}

#[tokio::test]
async fn caps() {
    let p = plane();
    let lim = ReadLimits {
        max_rows: 1,
        ..Default::default()
    };
    let e = p
        .execute(
            BUSY,
            &alice(),
            &params(),
            &ptypes(),
            &lim,
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, ReadError::RowCap));
    let e = p
        .execute(
            BUSY,
            &alice(),
            &params(),
            &ptypes(),
            &ReadLimits::default(),
            ScanCounter::new(2, 1 << 30),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, ReadError::ScanCap), "{e:?}");
    let e = p
        .execute(
            BUSY,
            &alice(),
            &Map::new(),
            &ptypes(),
            &ReadLimits::default(),
            ScanCounter::new(100, 1 << 30),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, ReadError::Param(_)));
}

#[tokio::test]
async fn aggregate_only_and_k_threshold() {
    let p = plane();
    let f = p
        .analyze(
            "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region",
            &alice(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
    assert!(f.aggregate_only);
    assert_eq!(f.min_group_size, Some(3));
    let f = p
        .analyze("SELECT * FROM crm.accounts", &alice(), &BTreeMap::new())
        .await
        .unwrap();
    assert!(!f.aggregate_only);
    let e = p
        .execute(
            "SELECT * FROM crm.accounts",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, ReadError::AggregateOnly(_)));
    // APAC has 1 account < k=3 → suppressed. EMEA 3, AMER 4 survive.
    let out = p
        .execute(
            "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region ORDER BY region",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap();
    let rows = arrowconv::batches_to_rows(&out.batches);
    assert_eq!(
        rows,
        vec![
            json!({"region": "AMER", "arr": 22000.0}),
            json!({"region": "EMEA", "arr": 6000.0})
        ]
    );
    // Targeting a single account through a filter yields nothing.
    let out = p
        .execute(
            "SELECT COUNT(*) AS n FROM crm.accounts WHERE account_id = 'a7'",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap();
    assert_eq!(out.rows, 0);
    // Projecting away the privacy unit before aggregating is refused.
    let e = p
        .execute(
            "WITH r AS (SELECT region, arr FROM crm.accounts) SELECT region, SUM(arr) FROM r GROUP BY region",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, ReadError::PrivacyUnit(_, _)), "{e:?}");
}

#[tokio::test]
async fn masks_and_owner_rows() {
    let p = plane();
    let out = p
        .execute(
            "SELECT email, COUNT(*) AS n FROM crm.accounts GROUP BY email",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap();
    assert_eq!(out.rows, 0); // every email is unique: k suppresses all groups
    let out = p
        .execute(
            "SELECT account_id, owner FROM crm.mine",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1000, 1 << 30),
        )
        .await
        .unwrap();
    let rows = arrowconv::batches_to_rows(&out.batches);
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|r| r["owner"] == json!("did:web:bob")));
}

/// Runs when REMIT_TEST_MYSQL_DSN points at a scratch MySQL/MariaDB database.
#[cfg(feature = "mysql")]
#[tokio::test]
async fn mysql_connector_pins_a_snapshot() {
    use mysql_async::prelude::Queryable;
    let Ok(dsn) = std::env::var("REMIT_TEST_MYSQL_DSN") else {
        eprintln!("skipping: REMIT_TEST_MYSQL_DSN not set");
        return;
    };
    let mut c = mysql_async::Pool::from_url(&dsn)
        .unwrap()
        .get_conn()
        .await
        .unwrap();
    for q in [
        "SET time_zone = '+00:00'",
        "DROP TABLE IF EXISTS events",
        "DROP TABLE IF EXISTS nothing",
        "CREATE TABLE nothing (id INT, at DATETIME)",
        "CREATE TABLE events (id BIGINT UNSIGNED, start_at TIMESTAMP NULL, end_at DATETIME, status VARCHAR(20) CHARACTER SET utf8mb4, title TEXT, price DECIMAL(10,2), ratio DOUBLE, day DATE, ok TINYINT(1), note VARCHAR(9) NULL)",
        "INSERT INTO events VALUES (1, '2026-11-24 10:00:00', '2026-11-24 11:00:00', 'confirmed', 'secret', 12.50, 0.25, '2026-11-24', 1, NULL), (2, '2026-11-25 10:00:00', '2026-11-25 11:00:00', 'cancelled', 'old', -3.00, 1e10, '2026-12-01', 0, 'naïve')",
    ] {
        c.query_drop(q).await.unwrap();
    }
    let src = SourceConfig {
        name: "calendar".into(),
        kind: "mysql".into(),
        tables: vec!["events".into(), "nothing".into()],
        dsn: Some(dsn.clone()),
        ..Default::default()
    };
    let mut store = Store::new();
    store
        .load_source(&src, std::path::Path::new("."))
        .await
        .unwrap();
    assert_eq!(store.get("calendar.nothing").unwrap().rows, 0);
    let v1 = store.get("calendar.events").unwrap().version.clone();
    assert!(v1.starts_with("mysql-"), "{v1}");
    let mut res = BTreeMap::new();
    let mut r = ResourceConfig::default();
    r.columns.insert(
        "title".into(),
        ColumnConfig {
            expose: false,
            ..Default::default()
        },
    );
    res.insert("calendar.events".into(), r);
    let plane = ReadPlane::new(&store, &res, "s").unwrap();
    let run = |sql: &'static str| {
        let plane = &plane;
        async move {
            let out = plane
                .execute(
                    sql,
                    &alice(),
                    &Default::default(),
                    &Default::default(),
                    &ReadLimits::default(),
                    ScanCounter::new(100, 1 << 30),
                )
                .await
                .unwrap();
            arrowconv::batches_to_rows(&out.batches)
        }
    };
    assert_eq!(
        run("SELECT id, start_at, end_at, status, ratio, ok, note FROM calendar.events ORDER BY id LIMIT 1").await,
        vec![json!({"id": 1, "start_at": "2026-11-24T10:00:00Z", "end_at": "2026-11-24T11:00:00Z", "status": "confirmed", "ratio": 0.25, "ok": 1, "note": null})]
    );
    let r = run("SELECT price, day, note FROM calendar.events WHERE id = 2").await;
    assert_eq!(r[0]["note"], json!("naïve"));
    assert_eq!(
        r[0]["price"]
            .to_string()
            .trim_matches('"')
            .parse::<f64>()
            .unwrap(),
        -3.0,
        "{r:?}"
    );
    assert!(
        r[0]["day"].as_str().unwrap().starts_with("2026-12-01"),
        "{r:?}"
    );
    // A change produces a new data version.
    c.query_drop("UPDATE events SET status = 'moved' WHERE id = 1")
        .await
        .unwrap();
    store
        .load_source(&src, std::path::Path::new("."))
        .await
        .unwrap();
    assert_ne!(store.get("calendar.events").unwrap().version, v1);
}

/// Runs when REMIT_TEST_PG_DSN points at a scratch Postgres database.
#[tokio::test]
async fn postgres_connector_pins_a_snapshot() {
    let Ok(dsn) = std::env::var("REMIT_TEST_PG_DSN") else {
        eprintln!("skipping: REMIT_TEST_PG_DSN not set");
        return;
    };
    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    client
        .batch_execute(
            "DROP TABLE IF EXISTS events; CREATE TABLE events (id int, start_at timestamptz, end_at timestamptz, status text, title text);
             INSERT INTO events VALUES (1, '2026-11-24T10:00:00Z', '2026-11-24T11:00:00Z', 'confirmed', 'secret'),
                                       (2, '2026-11-25T10:00:00Z', '2026-11-25T11:00:00Z', 'cancelled', 'old');",
        )
        .await
        .unwrap();
    let mut store = Store::new();
    let src = SourceConfig {
        name: "calendar".into(),
        kind: "postgres".into(),
        tables: vec!["events".into()],
        dsn: Some(dsn.clone()),
        ..Default::default()
    };
    store
        .load_source(&src, std::path::Path::new("."))
        .await
        .unwrap();
    let raw = store.get("calendar.events").unwrap();
    assert!(raw.version.starts_with("pg-snapshot:"), "{}", raw.version);
    assert_eq!(raw.rows, 2);
    let mut res = BTreeMap::new();
    let mut r = ResourceConfig::default();
    r.columns.insert(
        "title".into(),
        ColumnConfig {
            expose: false,
            ..Default::default()
        },
    );
    res.insert("calendar.events".into(), r);
    let plane = ReadPlane::new(&store, &res, "s").unwrap();
    let out = plane
        .execute(
            BUSY,
            &alice(),
            &params(),
            &ptypes(),
            &ReadLimits::default(),
            ScanCounter::new(100, 1 << 30),
        )
        .await
        .unwrap();
    assert_eq!(out.rows, 1);
    // Writes after the snapshot do not change the loaded data.
    client.batch_execute("INSERT INTO events VALUES (3, '2026-11-26T10:00:00Z', '2026-11-26T11:00:00Z', 'confirmed', 'new')").await.unwrap();
    assert_eq!(store.get("calendar.events").unwrap().rows, 2);
}

#[tokio::test]
async fn output_kinds_for_dp() {
    let p = plane();
    let f = p
        .analyze(
            "SELECT region, COUNT(*) AS n, SUM(arr) AS total FROM crm.accounts GROUP BY region",
            &alice(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
    eprintln!("{:?}", f.output_kinds);
    assert_eq!(f.output_kinds["region"], OutputKind::GroupKey);
    assert!(
        matches!(&f.output_kinds["n"], OutputKind::Aggregate { func, .. } if func == "count"),
        "{:?}",
        f.output_kinds
    );
    assert!(
        matches!(&f.output_kinds["total"], OutputKind::Aggregate { func, arg: Some(a) } if func == "sum" && a == "arr"),
        "{:?}",
        f.output_kinds
    );
}

#[tokio::test]
async fn fulltext_search_respects_views() {
    let mut store = Store::new();
    let schema = Arc::new(Schema::new(vec![
        Field::new("doc_id", DataType::Utf8, false),
        Field::new("body", DataType::Utf8, false),
        Field::new("secret", DataType::Utf8, false),
    ]));
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec!["d1", "d2", "d3"])),
            Arc::new(StringArray::from(vec![
                "refund policy for annual plans",
                "shipping times to Europe",
                "annual refund exceptions and refund limits",
            ])),
            Arc::new(StringArray::from(vec!["s1", "s2", "s3"])),
        ],
    )
    .unwrap();
    store.insert_batches("docs.chunks", schema, vec![b]);
    let mut r = ResourceConfig {
        operations: vec!["read".into(), "search".into()],
        ..Default::default()
    };
    r.columns.insert(
        "secret".into(),
        ColumnConfig {
            expose: false,
            ..Default::default()
        },
    );
    let mut res = BTreeMap::new();
    res.insert("docs.chunks".to_string(), r);
    let ix = IndexConfig {
        name: "docs".into(),
        kind: "fulltext".into(),
        table: "docs.chunks".into(),
        id_column: "doc_id".into(),
        text_column: Some("body".into()),
        vector_column: None,
        engine: None,
    };
    let plane = ReadPlane::new(&store, &res, "s")
        .unwrap()
        .with_indexes(std::slice::from_ref(&ix), &store)
        .unwrap();
    let sql = "SELECT s.id, s.score, c.body FROM fts('docs', $q, 2) s JOIN docs.chunks c ON c.doc_id = s.id ORDER BY s.score DESC";
    let pt: BTreeMap<String, ParamType> =
        [("q".to_string(), ParamType::String)].into_iter().collect();
    let f = plane.analyze(sql, &alice(), &pt).await.unwrap();
    assert!(f.tables.contains_key("docs.chunks"));
    let params = json!({"q": "refund"}).as_object().unwrap().clone();
    let out = plane
        .execute(
            sql,
            &alice(),
            &params,
            &pt,
            &ReadLimits::default(),
            ScanCounter::new(100, 1 << 30),
        )
        .await
        .unwrap();
    let rows = arrowconv::batches_to_rows(&out.batches);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], json!("d3"), "{rows:?}");
    // Quotes in params cannot break out of the literal.
    let evil = json!({"q": "x') UNION SELECT 1 --"})
        .as_object()
        .unwrap()
        .clone();
    assert!(plane
        .execute(
            sql,
            &alice(),
            &evil,
            &pt,
            &ReadLimits::default(),
            ScanCounter::new(100, 1 << 30)
        )
        .await
        .is_ok());
    // Hidden columns stay hidden.
    assert!(plane
        .analyze(
            "SELECT c.secret FROM fts('docs', $q, 2) s JOIN docs.chunks c ON c.doc_id = s.id",
            &alice(),
            &pt
        )
        .await
        .is_err());
    // Indexes over hidden columns are refused.
    let bad = IndexConfig {
        text_column: Some("secret".into()),
        ..ix
    };
    assert!(ReadPlane::new(&store, &res, "s")
        .unwrap()
        .with_indexes(&[bad], &store)
        .is_err());
}

// ------------------------------------------------------------------- DP

fn dp_plane(m: u64) -> ReadPlane {
    let mut store = Store::new();
    let schema = Arc::new(Schema::new(vec![
        Field::new("patient", DataType::Utf8, true),
        Field::new("ward", DataType::Utf8, false),
        Field::new("cost", DataType::Float64, true),
        Field::new("age", DataType::Int64, false),
    ]));
    // 50 patients; patient p0 has 1000 rows (an outlier contributor).
    let (mut pid, mut ward, mut cost, mut age) = (vec![], vec![], vec![], vec![]);
    for i in 0..50 {
        pid.push(Some(format!("p{i}")));
        ward.push(if i % 2 == 0 { "A" } else { "B" });
        cost.push(Some(100.0));
        age.push(40i64);
    }
    for _ in 0..1000 {
        pid.push(Some("p0".into()));
        ward.push("A");
        cost.push(Some(1e12));
        age.push(40);
    }
    pid.push(Some("p1".into()));
    ward.push("B");
    cost.push(None);
    age.push(40);
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(pid)),
            Arc::new(StringArray::from(ward)),
            Arc::new(Float64Array::from(cost)),
            Arc::new(datafusion::arrow::array::Int64Array::from(age)),
        ],
    )
    .unwrap();
    store.insert_batches("med.visits", schema, vec![b]);
    let s2 = Arc::new(Schema::new(vec![
        Field::new("patient", DataType::Utf8, false),
        Field::new("plan", DataType::Utf8, false),
    ]));
    let b2 = RecordBatch::try_new(
        s2.clone(),
        vec![
            Arc::new(StringArray::from(vec!["p0", "p1"])),
            Arc::new(StringArray::from(vec!["gold", "gold"])),
        ],
    )
    .unwrap();
    store.insert_batches("med.members", s2, vec![b2]);
    let s3 = Arc::new(Schema::new(vec![
        Field::new("ward", DataType::Utf8, false),
        Field::new("floor", DataType::Utf8, false),
    ]));
    let b3 = RecordBatch::try_new(
        s3.clone(),
        vec![
            Arc::new(StringArray::from(vec!["A", "B"])),
            Arc::new(StringArray::from(vec!["1", "2"])),
        ],
    )
    .unwrap();
    store.insert_batches("ref.wards", s3, vec![b3]);
    let mut res = BTreeMap::new();
    let dp = || {
        Some(DpConfig {
            epsilon_per_day: 1.0,
            max_contributions: m,
            delta: 1e-6,
            mechanism: "laplace".into(),
            ..Default::default()
        })
    };
    let mut v = ResourceConfig {
        dp: dp(),
        privacy_unit: Some("patient".into()),
        ..Default::default()
    };
    v.columns.insert(
        "cost".into(),
        ColumnConfig {
            expose: true,
            bounds: Some([0.0, 1000.0]),
            ..Default::default()
        },
    );
    v.columns.insert(
        "age".into(),
        ColumnConfig {
            expose: true,
            bounds: Some([0.0, 120.0]),
            ..Default::default()
        },
    );
    res.insert("med.visits".to_string(), v);
    res.insert(
        "med.members".to_string(),
        ResourceConfig {
            dp: dp(),
            privacy_unit: Some("patient".into()),
            ..Default::default()
        },
    );
    ReadPlane::new(&store, &res, "s").unwrap()
}

async fn dp_exact(p: &ReadPlane, sql: &str) -> Result<(DpShape, Vec<Value>), ReadError> {
    p.dp_shape(sql, &alice(), &BTreeMap::new()).await?;
    p.execute_dp(
        sql,
        &alice(),
        &Map::new(),
        &BTreeMap::new(),
        &ReadLimits::default(),
        ScanCounter::new(1 << 40, 1 << 40),
    )
    .await
}

#[tokio::test]
async fn dp_bounds_contributions_and_clamps() {
    let p = dp_plane(1);
    let (s, r) = dp_exact(&p, "SELECT ward, COUNT(*) AS n, SUM(cost) AS total, AVG(age) AS age FROM med.visits GROUP BY ward ORDER BY n DESC LIMIT 5").await.unwrap();
    assert_eq!(s.m, 1);
    assert!(s.grouped && !s.row_level);
    assert_eq!(s.order_by, vec![("n".to_string(), false, true)]);
    assert_eq!(s.limit, Some(5));
    assert!(matches!(s.columns[2].1, DpOut::Sum { lo, hi, .. } if lo == 0.0 && hi == 1000.0));
    let a = r.iter().find(|x| x["k0"] == "A").unwrap();
    // p0's 1001 rows count once; the 1e12 outlier is clamped to 1000.
    assert_eq!(a["a1"], json!(25));
    assert_eq!(a["__remit_units"], json!(25));
    assert!(a["a2"].as_f64().unwrap() <= 25.0 * 1000.0);
    // Larger m admits more rows per unit, and is reported for calibration.
    let p = dp_plane(10);
    let (s, r) = dp_exact(&p, "SELECT COUNT(*) AS n FROM med.visits")
        .await
        .unwrap();
    assert_eq!(s.m, 10);
    assert_eq!(r[0]["a0"], json!(50 + 9 + 1));
}

#[tokio::test]
async fn dp_expression_bounds_and_filters() {
    let p = dp_plane(1);
    let (s, _) = dp_exact(&p, "SELECT SUM(cost * 2 + age) AS x, SUM(CASE WHEN age > 30 THEN cost ELSE 0 END) AS y FROM med.visits WHERE ward = 'A' AND age BETWEEN 10 AND 90").await.unwrap();
    assert!(
        matches!(s.columns[0].1, DpOut::Sum { lo, hi, .. } if lo == 0.0 && hi == 2120.0),
        "{s:?}"
    );
    assert!(matches!(s.columns[1].1, DpOut::Sum { lo, hi, .. } if lo == 0.0 && hi == 1000.0));
    // Joins: on the privacy unit, or to public tables.
    assert!(dp_exact(&p, "SELECT m.plan, COUNT(*) AS n FROM med.visits v JOIN med.members m ON v.patient = m.patient GROUP BY m.plan").await.is_ok());
    assert!(dp_exact(&p, "SELECT w.floor, COUNT(DISTINCT v.patient) AS n FROM med.visits v JOIN ref.wards w ON v.ward = w.ward GROUP BY w.floor").await.is_ok());
}

#[tokio::test]
async fn dp_refuses_unbounded_or_leaky_plans() {
    let p = dp_plane(1);
    for sql in [
        // Exact HAVING, nested aggregates, windows, subquery predicates.
        "SELECT ward, COUNT(*) AS n FROM med.visits GROUP BY ward HAVING COUNT(*) > 3",
        "SELECT COUNT(*) AS n FROM (SELECT ward, COUNT(*) AS c FROM med.visits GROUP BY ward) t",
        "SELECT COUNT(*) AS n FROM med.visits WHERE cost > (SELECT MAX(age) FROM med.visits)",
        "SELECT COUNT(*) AS n FROM med.visits WHERE patient IN (SELECT patient FROM med.members)",
        "SELECT COUNT(*) AS n FROM (SELECT patient, ROW_NUMBER() OVER (ORDER BY cost) AS r FROM med.visits) t WHERE r < 3",
        "SELECT COUNT(*) AS n FROM (SELECT DISTINCT patient, ward FROM med.visits) t",
        "SELECT COUNT(*) AS n FROM (SELECT patient FROM med.visits ORDER BY cost LIMIT 1) t",
        // Raw values and unsupported aggregates.
        "SELECT patient, cost FROM med.visits",
        "SELECT MAX(cost) AS m FROM med.visits",
        "SELECT COUNT(DISTINCT ward) AS n FROM med.visits",
        "SELECT COUNT(*) * 2 AS n FROM med.visits",
        // Unbounded sums.
        "SELECT SUM(LENGTH(patient)) AS n FROM med.visits",
        // Joins that do not equate privacy units (one row owned by two units).
        "SELECT COUNT(*) AS n FROM med.visits v JOIN med.members m ON v.ward = m.plan",
        "SELECT COUNT(*) AS n FROM ref.wards w LEFT JOIN med.visits v ON v.ward = w.ward",
        // Spoofed privacy unit: an expression renamed to the unit column.
        "SELECT COUNT(*) AS n FROM (SELECT CONCAT(patient, ward) AS patient, cost FROM med.visits) t",
        "SELECT COUNT(DISTINCT patient) AS n FROM (SELECT CONCAT(ward, 'x') AS patient FROM med.visits) t",
        // Data-dependent failures (status-channel oracle).
        "SELECT COUNT(*) AS n FROM med.visits WHERE 1 / (age - 40) > 0",
        "SELECT COUNT(*) AS n FROM med.visits WHERE CAST(patient AS INT) = 1",
        "SELECT SUM(cost) FILTER (WHERE age % 2 = 0) AS n FROM med.visits",
    ] {
        let e = p.dp_shape(sql, &alice(), &BTreeMap::new()).await;
        assert!(matches!(e, Err(ReadError::Dp(_))), "{sql}: {e:?}");
    }
    // The exact path never runs on a DP-governed resource.
    let e = p
        .execute(
            "SELECT COUNT(*) AS n FROM med.visits",
            &alice(),
            &Map::new(),
            &BTreeMap::new(),
            &ReadLimits::default(),
            ScanCounter::new(1 << 40, 1 << 40),
        )
        .await;
    assert!(matches!(e, Err(ReadError::Dp(_))), "{e:?}");
}

// --------------------------------------------------------------- search

fn search_plane() -> ReadPlane {
    search_plane_with(None, true)
}

fn search_plane_with(engine: Option<&str>, row_policy: bool) -> ReadPlane {
    let mut store = Store::new();
    let schema = Arc::new(Schema::new(vec![
        Field::new("doc_id", DataType::Utf8, false),
        Field::new("body", DataType::Utf8, false),
        Field::new("owner", DataType::Utf8, false),
    ]));
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec!["mine", "theirs", "other"])),
            Arc::new(StringArray::from(vec![
                "merger plans",
                "secret merger target acme",
                "lunch menu",
            ])),
            Arc::new(StringArray::from(vec![
                "did:web:bob",
                "did:web:eve",
                "did:web:eve",
            ])),
        ],
    )
    .unwrap();
    store.insert_batches("docs.notes", schema, vec![b]);
    let mut res = BTreeMap::new();
    res.insert(
        "docs.notes".to_string(),
        ResourceConfig {
            operations: vec!["read".into(), "search".into()],
            owner_column: row_policy.then(|| "owner".into()),
            ..Default::default()
        },
    );
    let ix = IndexConfig {
        name: "notes".into(),
        kind: "fulltext".into(),
        table: "docs.notes".into(),
        id_column: "doc_id".into(),
        text_column: Some("body".into()),
        vector_column: None,
        engine: engine.map(Into::into),
    };
    ReadPlane::new(&store, &res, "s")
        .unwrap()
        .with_indexes(&[ix], &store)
        .unwrap()
}

#[tokio::test]
async fn search_is_not_an_oracle_over_hidden_rows() {
    let p = search_plane();
    let pt: BTreeMap<String, ParamType> =
        [("q".to_string(), ParamType::String)].into_iter().collect();
    let run = |q: &str| {
        let params = json!({"q": q}).as_object().unwrap().clone();
        let (p, pt) = (&p, pt.clone());
        async move {
            let out = p
                .execute(
                    "SELECT id, score FROM fts('notes', $q, 10)",
                    &alice(),
                    &params,
                    &pt,
                    &ReadLimits::default(),
                    ScanCounter::new(100, 1 << 30),
                )
                .await
                .unwrap();
            arrowconv::batches_to_rows(&out.batches)
        }
    };
    assert!(
        run("acme").await.is_empty(),
        "another owner's row is not searchable"
    );
    let r = run("merger").await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["id"], json!("mine"));
    // Scores do not depend on hidden documents: N = 1, df = 1, dl = avgdl.
    let expect = ((1.0f64 - 1.0 + 0.5) / (1.0 + 0.5) + 1.0).ln() * 2.2 / (1.0 + 1.2);
    assert!(
        (r[0]["score"].as_f64().unwrap() - expect).abs() < 1e-5,
        "{r:?}"
    );
}

#[cfg(feature = "tantivy")]
#[tokio::test]
async fn tantivy_ranks_stems_and_never_scores_over_hidden_rows() {
    let pt: BTreeMap<String, ParamType> =
        [("q".to_string(), ParamType::String)].into_iter().collect();
    let run = |p: ReadPlane, q: &'static str| {
        let pt = pt.clone();
        async move {
            let params = json!({"q": q}).as_object().unwrap().clone();
            let out = p
                .execute(
                    "SELECT id, score FROM fts('notes', $q, 10)",
                    &alice(),
                    &params,
                    &pt,
                    &ReadLimits::default(),
                    ScanCounter::new(100, 1 << 30),
                )
                .await
                .unwrap();
            arrowconv::batches_to_rows(&out.batches)
        }
    };
    let open = || search_plane_with(Some("tantivy"), false);
    // Only Tantivy's stemmer maps "mergers" to "merger".
    let r = run(open(), "mergers").await;
    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!(
        r[0]["id"],
        json!("mine"),
        "the shorter document ranks first: {r:?}"
    );
    assert_eq!(r, run(open(), "mergers").await, "scores are reproducible");
    // Query syntax is not interpreted.
    assert!(run(open(), "body:* OR ord:[0 TO 9]").await.is_empty());
    // Under a row policy the hidden rows neither match nor affect scores.
    let filtered = run(search_plane_with(Some("tantivy"), true), "merger").await;
    assert_eq!(filtered, run(search_plane(), "merger").await);
    assert!(run(search_plane_with(Some("tantivy"), true), "acme")
        .await
        .is_empty());
}

#[tokio::test]
async fn unknown_index_engine_is_refused() {
    let mut store = Store::new();
    let schema = Arc::new(Schema::new(vec![
        Field::new("doc_id", DataType::Utf8, false),
        Field::new("body", DataType::Utf8, false),
    ]));
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec!["a"])),
            Arc::new(StringArray::from(vec!["b"])),
        ],
    )
    .unwrap();
    store.insert_batches("docs.notes", schema, vec![b]);
    let res: BTreeMap<_, _> = [(
        "docs.notes".to_string(),
        ResourceConfig {
            operations: vec!["read".into(), "search".into()],
            ..Default::default()
        },
    )]
    .into_iter()
    .collect();
    let ix = IndexConfig {
        name: "n".into(),
        kind: "fulltext".into(),
        table: "docs.notes".into(),
        id_column: "doc_id".into(),
        text_column: Some("body".into()),
        vector_column: None,
        engine: Some("lucene".into()),
    };
    assert!(ReadPlane::new(&store, &res, "s")
        .unwrap()
        .with_indexes(&[ix], &store)
        .is_err());
}

#[tokio::test]
async fn param_values_are_never_rescanned_for_placeholders() {
    let p = search_plane();
    let pt: BTreeMap<String, ParamType> = [
        ("query".to_string(), ParamType::String),
        ("b".to_string(), ParamType::String),
    ]
    .into_iter()
    .collect();
    let sql = "SELECT n.body, 'it''s $b' AS s FROM fts('notes', $query, 10) f JOIN docs.notes n ON n.doc_id = f.id WHERE n.body <> $b";
    // `$query`'s value names `$b`; `$b`'s value tries to break out of the literal.
    let params =
        json!({"query": "merger $b", "b": ", 1) f UNION SELECT doc_id, owner FROM docs.notes --"})
            .as_object()
            .unwrap()
            .clone();
    let out = p
        .execute(
            sql,
            &alice(),
            &params,
            &pt,
            &ReadLimits::default(),
            ScanCounter::new(100, 1 << 30),
        )
        .await
        .unwrap();
    let rows = arrowconv::batches_to_rows(&out.batches);
    assert_eq!(rows, vec![json!({"body": "merger plans", "s": "it's $b"})]);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
    /// Policy rewrites never widen visible columns or rows: whatever the
    /// projection/predicate, results only contain exposed columns and owner rows.
    #[test]
    fn policy_rewrites_never_widen(cols in proptest::collection::vec(0usize..6, 1..4), star in proptest::bool::ANY, pred in 0usize..4) {
        let names = ["account_id", "region", "arr", "owner", "email", "*"];
        let sel = if star { "*".to_string() } else { cols.iter().enumerate().map(|(i, c)| if names[*c] == "*" { format!("1 AS one{i}") } else { format!("{} AS c{i}_{}", names[*c], names[*c]) }).collect::<Vec<_>>().join(", ") };
        let w = ["", "WHERE owner = 'did:web:eve'", "WHERE 1 = 1 OR owner <> 'x'", "WHERE owner IS NOT NULL"][pred];
        let sql = format!("SELECT {sel}, owner AS o FROM (SELECT * FROM crm.mine) t {w}");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let rows = rt.block_on(async {
            let p = plane();
            let out = p.execute(&sql, &alice(), &Map::new(), &BTreeMap::new(), &ReadLimits::default(), ScanCounter::new(1000, 1 << 30)).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
            arrowconv::batches_to_rows(&out.batches)
        });
        for r in &rows {
            proptest::prop_assert_eq!(&r["o"], &json!("did:web:bob"));
            proptest::prop_assert!(r.as_object().unwrap().keys().all(|k| k != "title"));
        }
        if pred == 1 { proptest::prop_assert!(rows.is_empty()); }
    }
}

#[tokio::test]
async fn sqlite_versions_include_committed_wal_rows() {
    let dir = std::env::temp_dir().join(format!("remit-sqlite-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("snapshot.sqlite");
    let _ = std::fs::remove_file(&path);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE items(n INTEGER); INSERT INTO items VALUES (1); PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;").unwrap();
    let src = SourceConfig {
        name: "db".into(),
        kind: "sqlite".into(),
        path: Some("snapshot.sqlite".into()),
        ..Default::default()
    };
    let mut store = Store::new();
    store.load_source(&src, &dir).await.unwrap();
    let before = store.get("db.items").unwrap().version.clone();
    conn.execute("INSERT INTO items VALUES (2)", []).unwrap();
    store.load_source(&src, &dir).await.unwrap();
    let after = store.get("db.items").unwrap();
    assert_eq!(after.rows, 2);
    assert_ne!(before, after.version);
    let version = after.version.clone();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    store.load_source(&src, &dir).await.unwrap();
    assert_eq!(version, store.get("db.items").unwrap().version);
    drop(conn);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn postgres_columns_share_row_order() {
    let Ok(dsn) = std::env::var("REMIT_TEST_PG_DSN") else {
        return;
    };
    let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let task = tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS remit_column_pairs; CREATE TABLE remit_column_pairs(id INTEGER, tag TEXT, filler TEXT); INSERT INTO remit_column_pairs SELECT i, 'n' || lpad((10001-i)::text,5,'0'), repeat(md5(i::text),24) FROM generate_series(1,10000) AS i; CREATE INDEX remit_column_tags ON remit_column_pairs(tag);").await.unwrap();
    client
        .batch_execute("VACUUM (ANALYZE) remit_column_pairs")
        .await
        .unwrap();
    let tables = crate::postgres::load(&dsn, &["remit_column_pairs".into()])
        .await
        .unwrap();
    let batch = &tables[0].1.batches[0];
    let ids = batch
        .column(0)
        .as_any()
        .downcast_ref::<datafusion::arrow::array::Int64Array>()
        .unwrap();
    let tags = batch
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    for i in 0..batch.num_rows() {
        assert_eq!(tags.value(i), format!("n{:05}", 10001 - ids.value(i)));
    }
    client
        .batch_execute("DROP TABLE remit_column_pairs")
        .await
        .unwrap();
    task.abort();
}
