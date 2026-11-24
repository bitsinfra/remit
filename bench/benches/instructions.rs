//! Instruction-count benchmarks (Valgrind/callgrind through iai-callgrind): the
//! CI perf gate. Wall-clock noise cannot hide a regression here.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use serde_json::json;

fn rt_json() -> serde_json::Value {
    json!({"list": {"max": 3, "of": {"struct": {
        "start": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}},
        "end": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}}}}}})
}

fn envelope() -> (Vec<u8>, remit_wire::Manifest) {
    let s = remit_wire::Signer::from_seed([7; 32], None);
    let m = remit_wire::Manifest::from_value(json!({
        "remit": "0.1", "sender": s.id(), "holder": "did:web:alice.vault.example",
        "issued_at": "2026-11-21T10:00:00Z", "expires_at": "2026-11-21T10:05:00Z", "nonce": "q3V0aaaaaaaa", "purpose": "scheduling", "mode": "query",
        "reads": {"q": {"sql": "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from", "params": {"from": "timestamp", "until": "timestamp"}, "max_rows": 500}},
        "params": {"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z"}, "returns": rt_json()
    }))
    .unwrap();
    (
        serde_json::to_vec(&remit_wire::sign_manifest(&m, &s)).unwrap(),
        m,
    )
}

#[library_benchmark]
#[bench::typical(envelope())]
fn decode_authn((b, _): (Vec<u8>, remit_wire::Manifest)) -> usize {
    let e: remit_wire::Envelope = serde_json::from_slice(black_box(&b)).unwrap();
    remit_wire::open_manifest(&e, remit_wire::public_key_from_did_key)
        .unwrap()
        .1
        .len()
}

#[library_benchmark]
#[bench::typical(envelope())]
fn remit_id((_, m): (Vec<u8>, remit_wire::Manifest)) -> String {
    black_box(&m).remit_id()
}

#[library_benchmark]
#[bench::typical(envelope())]
fn bind_and_capacity((_, m): (Vec<u8>, remit_wire::Manifest)) -> u64 {
    remit_types::RtTemplate::from_json(&m.returns)
        .unwrap()
        .bind(m.params.as_ref().unwrap())
        .unwrap()
        .capacity_bits_ceil()
}

#[library_benchmark]
fn sql_profile() -> bool {
    remit_sql::check(black_box("SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'"), &Default::default()).is_ok()
}

#[library_benchmark]
fn js_early_errors() -> usize {
    remit_analyze::check_js(black_box("export default function main({busy}, p) { const out = []; for (const r of busy(p).rows()) out.push(r); return out.slice(0, 3); }"), "main").len()
}

fn ledger() -> (remit_policy::Ledger, remit_policy::Ask) {
    let ask = remit_policy::Ask {
        principal: "did:web:a".into(),
        verified: true,
        datasets: vec!["calendar".into()],
        bits: 8,
        fuel: 1000,
        ..Default::default()
    };
    (
        remit_policy::Ledger::open(Default::default(), None).unwrap(),
        ask,
    )
}

#[library_benchmark]
#[bench::typical(ledger())]
fn reserve_settle((l, ask): (remit_policy::Ledger, remit_policy::Ask)) -> u32 {
    let r = l.reserve(black_box(&ask), 1_795_000_000_000).unwrap();
    l.settle(
        &r,
        remit_policy::Actual::used(10, 8, remit_policy::Privacy::ZERO),
    );
    l.in_flight()
}

library_benchmark_group!(name = admission; benchmarks = decode_authn, remit_id, bind_and_capacity, sql_profile, js_early_errors, reserve_settle);

/// Instantiate + trivial run from a pre-initialized engine (the kernel path).
mod instantiate {
    use super::*;
    use remit_kernel::{
        encode_params, EngineConfig, KernelEngine, KernelJob, KernelLimits, StaticReads,
    };

    pub fn engine() -> (tokio::runtime::Runtime, std::sync::Arc<KernelEngine>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../engines/js/dist/remit_engine_js.wasm");
        let e = rt
            .block_on(KernelEngine::new(EngineConfig {
                component: path,
                cache_dir: Some(
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../target/callgrind-engine-cache"
                    )
                    .into(),
                ),
                baseline_cpu: true,
                pool_instances: 4,
                warm_instances: 1,
                ..Default::default()
            }))
            .unwrap();
        (rt, e)
    }

    #[library_benchmark]
    #[bench::trivial(engine())]
    fn trivial_kernel((rt, e): (tokio::runtime::Runtime, std::sync::Arc<KernelEngine>)) -> u64 {
        let job = KernelJob {
            source: "export default function main() { return 1; }".into(),
            entry: "main".into(),
            params_cbor: encode_params(&serde_json::Map::new(), &[]),
            nonce: "bench-nonce".into(),
            issued_at_ms: 0,
            limits: KernelLimits {
                fuel: 10_000_000,
                memory_bytes: 64 << 20,
                wall_ms: 60_000,
            },
            component: false,
            compiled: None,
        };
        let o = rt.block_on(e.run(
            &job,
            Box::new(StaticReads {
                tables: Default::default(),
                max_calls: Default::default(),
                calls: Default::default(),
            }),
        ));
        assert_eq!(o.status, remit_kernel::Status::Ok);
        o.fuel_used
    }

    library_benchmark_group!(name = kernel; benchmarks = trivial_kernel);
}
use instantiate::kernel;

main!(library_benchmark_groups = admission, kernel);
