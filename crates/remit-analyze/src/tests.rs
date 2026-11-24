use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, StringArray, TimestampMillisecondArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use remit_read::{ColumnConfig, Principal, ReadPlane, ResourceConfig, Store};
use remit_wire::Manifest;
use serde_json::{json, Value};

use crate::*;

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
            Arc::new(TimestampMillisecondArray::from(vec![0i64])),
            Arc::new(TimestampMillisecondArray::from(vec![0i64])),
            Arc::new(StringArray::from(vec!["confirmed"])),
            Arc::new(StringArray::from(vec!["x"])),
        ],
    )
    .unwrap();
    store.insert_batches("calendar.events", schema, vec![b]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("account_id", DataType::Utf8, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("arr", DataType::Float64, false),
    ]));
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec!["a"])),
            Arc::new(StringArray::from(vec!["EMEA"])),
            Arc::new(Float64Array::from(vec![1.0])),
        ],
    )
    .unwrap();
    store.insert_batches("crm.accounts", schema, vec![b]);
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
    res.insert(
        "crm.accounts".to_string(),
        ResourceConfig {
            aggregate_only: true,
            k: Some(20),
            privacy_unit: Some("account_id".into()),
            ..Default::default()
        },
    );
    ReadPlane::new(&store, &res, "s").unwrap()
}

fn who() -> Principal {
    Principal {
        id: "did:web:travel-agent.example".into(),
        groups: vec![],
    }
}

fn kernel_manifest() -> Value {
    json!({
        "remit": "0.1", "sender": "did:web:travel-agent.example", "holder": "did:web:alice.vault.example",
        "issued_at": "2026-11-21T10:00:00Z", "expires_at": "2026-11-21T10:05:00Z", "nonce": "q3V0aaaaaa",
        "purpose": "scheduling", "mode": "kernel",
        "reads": {"busy": {
            "sql": "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'",
            "params": {"from": "timestamp", "until": "timestamp"}, "max_rows": 500, "max_calls": 1}},
        "code": {"lang": "js/es2023", "entry": "main", "source_sha256": remit_wire::sha256_hex(b"export default function main({busy}, p) { return []; }"),
                 "source": "export default function main({busy}, p) { return []; }"},
        "params": {"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 120},
        "limits": {"fuel": 20000000, "memory_bytes": 16777216, "wall_ms": 250, "output_bytes": 1024},
        "returns": {"list": {"max": 3, "of": {"struct": {
            "start": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}},
            "end": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}}}}}}
    })
}

#[tokio::test]
async fn plan_example_facts() {
    let m = Manifest::from_value(kernel_manifest()).unwrap();
    let a = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap();
    let f = &a.facts;
    assert_eq!(f.result_bits, 65 + 3);
    let r = &f.resources["calendar.events"];
    assert_eq!(
        r.columns.iter().cloned().collect::<Vec<_>>(),
        vec!["end_at", "start_at", "status"]
    );
    assert!(r.actions.contains("read") && r.actions.contains("run_kernel"));
    assert_eq!(r.max_rows_total, 500);
    assert!(!f.aggregate_only);
    let ctx = f.cedar_context("calendar.events");
    assert_eq!(ctx["result_bits"], json!(68));
    let card = access_card(&m, &a);
    assert_eq!(card["result_bits_max"], json!(68));
}

#[tokio::test]
async fn diagnostics_are_located_and_actionable() {
    let mut v = kernel_manifest();
    v["returns"] = json!({"list": {"of": {"string": {}}}});
    let m = Manifest::from_value(v).unwrap();
    let d = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0101");
    assert_eq!(d[0].path, "/returns/list/max");
    assert!(d[0].hint.is_some());

    let mut v = kernel_manifest();
    v["reads"]["busy"]["sql"] = json!("SELECT title FROM calendar.events WHERE start_at < now()");
    let m = Manifest::from_value(v).unwrap();
    let d = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0205");
    assert!(d[0].span.is_some());

    let mut v = kernel_manifest();
    v["reads"]["busy"]["sql"] = json!("SELECT title FROM calendar.events");
    let m = Manifest::from_value(v).unwrap();
    let d = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0301");
    assert!(d[0].message.contains("title"));

    let mut v = kernel_manifest();
    v["reads"]["busy"]["params"] = json!({"from": "timestamp"});
    let m = Manifest::from_value(v).unwrap();
    let d = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0110");
    assert!(d[0].fix.is_some());

    let mut v = kernel_manifest();
    v["limits"]["bits"] = json!(32);
    let m = Manifest::from_value(v).unwrap();
    let d = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0130");
}

#[tokio::test]
async fn query_mode_shapes_and_aggregate_only() {
    let q = |sql: &str, returns: Value| {
        Manifest::from_value(json!({
            "remit": "0.1", "sender": "did:web:p", "holder": "did:web:h", "issued_at": "2026-11-21T10:00:00Z",
            "expires_at": "2026-11-21T10:05:00Z", "nonce": "nonce-0001", "purpose": "analytics", "mode": "query",
            "reads": {"q": {"sql": sql, "max_rows": 20}}, "params": {}, "returns": returns
        }))
        .unwrap()
    };
    let rt = json!({"list": {"max": 20, "of": {"struct": {"region": {"enum": ["EMEA", "AMER", "APAC"]}, "arr": {"float": {"min": 0, "max": 1e9, "precision": 1000}}}}}});
    let a = analyze(
        &q(
            "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region",
            rt.clone(),
        ),
        &plane(),
        &who(),
        &HolderLimits::default(),
    )
    .await
    .unwrap();
    assert!(a.facts.aggregate_only);
    assert_eq!(a.facts.min_group_size, Some(20));
    assert!(a.facts.resources["crm.accounts"]
        .actions
        .contains("aggregate"));
    let d = analyze(
        &q("SELECT region, arr FROM crm.accounts", rt.clone()),
        &plane(),
        &who(),
        &HolderLimits::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0304");
    let d = analyze(
        &q(
            "SELECT region, SUM(arr) AS total FROM crm.accounts GROUP BY region",
            rt.clone(),
        ),
        &plane(),
        &who(),
        &HolderLimits::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(d[0].code, "RMT-E0120");
    // JSON Schema returns are accepted too (Zod 4 / Standard JSON Schema).
    let js = json!({"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "array", "maxItems": 20, "items": {"type": "object",
        "properties": {"region": {"type": "string", "enum": ["EMEA", "AMER", "APAC"]}, "arr": {"type": "number", "minimum": 0, "maximum": 1e9}},
        "required": ["region", "arr"], "additionalProperties": false}});
    let a = analyze(
        &q(
            "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region",
            js,
        ),
        &plane(),
        &who(),
        &HolderLimits::default(),
    )
    .await
    .unwrap();
    assert!(a.warnings.iter().any(|w| w.code == "RMT-W0101"));
}

#[tokio::test]
async fn clamps_become_counter_offers() {
    let mut v = kernel_manifest();
    v["limits"]["wall_ms"] = json!(999_999);
    let m = Manifest::from_value(v).unwrap();
    let a = analyze(&m, &plane(), &who(), &HolderLimits::default())
        .await
        .unwrap();
    assert_eq!(
        a.clamps,
        vec![json!({"op": "replace", "path": "/limits/wall_ms", "value": 10_000})]
    );
    assert_eq!(a.limits.wall_ms, 10_000);
}
