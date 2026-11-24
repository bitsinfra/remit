//! Micro-benchmarks for admission stages (the cached-plan path is dominated
//! by these). End-to-end numbers: `remit bench`.

use std::collections::{BTreeMap, BTreeSet};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;

fn rt_json() -> serde_json::Value {
    json!({"list": {"max": 3, "of": {"struct": {
        "start": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}},
        "end": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}}}}}})
}

fn manifest(s: &remit_wire::Signer) -> remit_wire::Manifest {
    remit_wire::Manifest::from_value(json!({
        "remit": "0.1", "sender": s.id(), "holder": "did:web:alice.vault.example",
        "issued_at": "2026-11-21T10:00:00Z", "expires_at": "2026-11-21T10:05:00Z", "nonce": "q3V0aaaaaaaa",
        "purpose": "scheduling", "mode": "query",
        "reads": {"q": {"sql": "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from", "params": {"from": "timestamp", "until": "timestamp"}, "max_rows": 500}},
        "params": {"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z"},
        "returns": rt_json()
    }))
    .unwrap()
}

fn bench(c: &mut Criterion) {
    let s = remit_wire::Signer::generate(None);
    let m = manifest(&s);
    let env = remit_wire::sign_manifest(&m, &s);
    let env_bytes = serde_json::to_vec(&env).unwrap();
    let params = m.params.clone().unwrap();

    c.bench_function("decode+authn (DSSE Ed25519 + JCS check)", |b| {
        b.iter(|| {
            let e: remit_wire::Envelope = serde_json::from_slice(black_box(&env_bytes)).unwrap();
            remit_wire::open_manifest(&e, remit_wire::public_key_from_did_key).unwrap()
        })
    });
    c.bench_function("remit_id", |b| b.iter(|| black_box(&m).remit_id()));
    c.bench_function("rt bind + capacity", |b| {
        let t = remit_types::RtTemplate::from_json(&rt_json()).unwrap();
        b.iter(|| t.bind(black_box(&params)).unwrap().capacity_bits())
    });
    c.bench_function("sql profile check", |b| {
        b.iter(|| remit_sql::check(black_box("SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'"), &Default::default()).unwrap())
    });
    c.bench_function("js early errors (oxc, free-slots kernel)", |b| {
        let src = "export default function main({busy}, p) { const out = []; for (const r of busy(p).rows()) out.push(r); return out.slice(0, 3); }";
        b.iter(|| remit_analyze::check_js(black_box(src), "main"))
    });
    // Cedar decision over facts.
    let mut res = BTreeMap::new();
    res.insert(
        "calendar.events".to_string(),
        remit_read::ResourceConfig {
            purposes: vec!["scheduling".into()],
            max_bits: Some(128),
            ..Default::default()
        },
    );
    let text = remit_policy::presets::assemble(&["personal-vault".into()], &[]).unwrap();
    let eng = remit_policy::PolicyEngine::new(&text, &res, &["verified-agents".into()]).unwrap();
    let mut resources = BTreeMap::new();
    resources.insert(
        "calendar.events".to_string(),
        remit_analyze::ResourceFacts {
            columns: ["start_at", "end_at"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            aggregate_only: false,
            actions: ["read", "run_kernel"]
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>(),
            max_rows_total: 500,
        },
    );
    let facts = remit_analyze::Facts {
        mode: "kernel".into(),
        purpose: "scheduling".into(),
        resources,
        ops: BTreeSet::new(),
        aggregate_only: false,
        min_group_size: None,
        result_bits: 68,
        capacity_bits: 64.4,
        fuel: 20_000_000,
        memory_bytes: 1 << 24,
        wall_ms: 250,
        scan_rows: 1000,
        output_bytes: 1024,
        max_rows_total: 500,
        epsilon_milli: 0,
        standing_approval: false,
        authority: BTreeSet::new(),
        cost: json!({}),
    };
    let p = remit_policy::PrincipalInfo {
        id: "did:web:travel-agent.example".into(),
        groups: vec!["verified-agents".into()],
        verified: true,
        ..Default::default()
    };
    c.bench_function("cedar decide (2 requests)", |b| {
        b.iter(|| assert!(eng.decide(black_box(&p), black_box(&facts)).allowed))
    });
    let ledger = remit_policy::Ledger::open(
        remit_policy::BudgetConfig {
            bits_per_principal_per_day: u64::MAX / 2,
            fuel_per_principal_per_minute: u64::MAX / 2,
            fuel_per_principal_per_day: u64::MAX / 2,
            bits_global_per_day: u64::MAX / 2,
            concurrency_per_principal: u32::MAX,
            concurrency_global: u32::MAX,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let ask = remit_policy::Ask {
        principal: "did:web:a".into(),
        verified: true,
        datasets: vec!["calendar".into()],
        bits: 68,
        fuel: 1000,
        ..Default::default()
    };
    c.bench_function("budget reserve + settle", |b| {
        b.iter(|| {
            let r = ledger.reserve(black_box(&ask), 1_795_000_000_000).unwrap();
            ledger.settle(
                &r,
                remit_policy::Actual::used(10, 68, remit_policy::Privacy::ZERO),
            );
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
