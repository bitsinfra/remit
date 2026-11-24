use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::array::TimestampMillisecondArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use serde_json::{json, Value};
use tokio::sync::OnceCell;

use crate::*;

static ENGINE: OnceCell<Arc<KernelEngine>> = OnceCell::const_new();

async fn engine() -> Arc<KernelEngine> {
    ENGINE
        .get_or_init(|| async {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            KernelEngine::new(EngineConfig {
                component: root.join("engines/js/dist/remit_engine_js.wasm"),
                cache_dir: Some(root.join("target/remit-engine-cache")),
                pool_instances: 16,
                ..Default::default()
            })
            .await
            .expect("engine")
        })
        .await
        .clone()
}

fn ms(s: &str) -> i64 {
    time_parse(s).unwrap()
}

fn busy_table() -> HostTable {
    let ts = DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()));
    let schema = Arc::new(Schema::new(vec![
        Field::new("start_at", ts.clone(), false),
        Field::new("end_at", ts, false),
    ]));
    let b = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(
                TimestampMillisecondArray::from(vec![
                    ms("2026-11-24T10:00:00Z"),
                    ms("2026-11-24T13:00:00Z"),
                    ms("2026-11-25T09:00:00Z"),
                ])
                .with_timezone("UTC"),
            ),
            Arc::new(
                TimestampMillisecondArray::from(vec![
                    ms("2026-11-24T11:00:00Z"),
                    ms("2026-11-24T17:30:00Z"),
                    ms("2026-11-25T18:00:00Z"),
                ])
                .with_timezone("UTC"),
            ),
        ],
    )
    .unwrap();
    HostTable {
        schema_ipc: remit_read::arrowconv::ipc_schema_message(&schema),
        batches_ipc: vec![ByteBuf(remit_read::arrowconv::ipc_batch_message(&b))],
        rows: 3,
        bytes: b.get_array_memory_size() as u64,
    }
}

fn reads(max_calls: u32) -> Box<dyn ReadHost> {
    let mut tables = BTreeMap::new();
    tables.insert("busy".to_string(), busy_table());
    let mut mc = BTreeMap::new();
    mc.insert("busy".to_string(), max_calls);
    Box::new(StaticReads {
        tables,
        max_calls: mc,
        calls: BTreeMap::new(),
    })
}

fn job(source: &str, params: Value, fuel: u64) -> KernelJob {
    let p = params.as_object().unwrap().clone();
    KernelJob {
        source: source.into(),
        entry: "main".into(),
        params_cbor: encode_params(&p, &["from".to_string(), "until".to_string()]),
        nonce: "nonce-123456".into(),
        issued_at_ms: ms("2026-11-21T10:00:00Z"),
        limits: KernelLimits {
            fuel,
            memory_bytes: 64 << 20,
            wall_ms: 5_000,
        },
        component: false,
        compiled: None,
    }
}

fn result(o: &KernelOutcome) -> Value {
    assert_eq!(o.status, Status::Ok, "log: {}", o.log);
    cbor_to_json(&ciborium::from_reader(o.result_cbor.as_slice()).unwrap())
}

pub const FREE_SLOTS: &str = r#"
export default function main({ busy }, p) {
  const H = 3_600_000, need = p.minutes * 60_000, step = 15 * 60_000;
  const taken = busy(p).rows().map(r => [+r.start_at, +r.end_at]).sort((a, b) => a[0] - b[0]);
  const out = [];
  for (let day = +p.from; day < +p.until && out.length < 3; day += 24 * H) {
    let t = day + 9 * H; const close = day + 18 * H;
    for (const [s, e] of taken) {
      if (e <= t || s >= close) continue;
      if (s - t >= need && out.length < 3) out.push({ start: new Date(t), end: new Date(t + need) });
      t = Math.max(t, Math.ceil(e / step) * step);
    }
    if (out.length < 3 && close - t >= need) out.push({ start: new Date(t), end: new Date(t + need) });
  }
  return out;
}
"#;

#[tokio::test(flavor = "multi_thread")]
async fn plan_example_free_slots() {
    let e = engine().await;
    let o = e
        .run(&job(FREE_SLOTS, json!({"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 120}), 50_000_000), reads(1))
        .await;
    let v = result(&o);
    assert_eq!(
        v,
        json!([
            {"start": "2026-11-24T11:00:00Z", "end": "2026-11-24T13:00:00Z"},
            {"start": "2026-11-26T09:00:00Z", "end": "2026-11-26T11:00:00Z"},
            {"start": "2026-11-27T09:00:00Z", "end": "2026-11-27T11:00:00Z"}
        ])
    );
    assert!(o.fuel_used > 0 && o.host_fuel > 0);
    eprintln!(
        "free-slots: fuel={} host_fuel={} wall={}µs instantiate={}µs baseline_load={}",
        o.fuel_used,
        o.host_fuel,
        o.wall_us,
        o.instantiate_us,
        e.baseline_load_fuel()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deterministic_environment() {
    let e = engine().await;
    let src = r#"export default function main(_r, p) {
        return { now: Date.now(), r: Math.random(), fetch: typeof fetch, timers: typeof setTimeout,
                 req: typeof require, deno: typeof Deno, proc: typeof process, wasm: typeof WebAssembly };
    }"#;
    let a = result(&e.run(&job(src, json!({}), 50_000_000), reads(1)).await);
    let b = result(&e.run(&job(src, json!({}), 50_000_000), reads(1)).await);
    assert_eq!(a, b, "same nonce → same result");
    assert_eq!(a["now"], json!(ms("2026-11-21T10:00:00Z")));
    for k in ["fetch", "timers", "req", "deno", "proc", "wasm"] {
        assert_eq!(a[k], json!("undefined"), "{k}");
    }
    let mut j = job(src, json!({}), 50_000_000);
    j.nonce = "another-nonce".into();
    let c = result(&e.run(&j, reads(1)).await);
    assert_ne!(a["r"], c["r"], "different nonce → different PRNG stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn fuel_and_wall_limits() {
    let e = engine().await;
    let o = e
        .run(
            &job(
                "export default function main() { for (;;) {} }",
                json!({}),
                5_000_000,
            ),
            reads(1),
        )
        .await;
    assert_eq!(o.status, Status::LimitExceeded, "{}", o.log);
    // Top-level code is metered too.
    let o = e
        .run(
            &job(
                "for (;;) {} export default function main() {}",
                json!({}),
                5_000_000,
            ),
            reads(1),
        )
        .await;
    assert_eq!(o.status, Status::LimitExceeded, "{}", o.log);
    // Wall deadline with effectively unlimited fuel.
    let mut j = job(
        "export default function main() { for (;;) {} }",
        json!({}),
        u64::MAX / 8,
    );
    j.limits.wall_ms = 200;
    let t = std::time::Instant::now();
    let o = e.run(&j, reads(1)).await;
    assert_eq!(o.status, Status::LimitExceeded);
    assert!(t.elapsed().as_millis() < 2_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_limit() {
    let e = engine().await;
    let mut j = job("export default function main() { const a = []; for (;;) a.push(new Array(100000).fill(1)); }", json!({}), u64::MAX / 8);
    j.limits.memory_bytes = 32 << 20;
    j.limits.wall_ms = 20_000;
    let o = e.run(&j, reads(1)).await;
    assert_eq!(o.status, Status::LimitExceeded, "{}", o.log);
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_and_caps() {
    let e = engine().await;
    let o = e
        .run(
            &job("export default function main( {", json!({}), 50_000_000),
            reads(1),
        )
        .await;
    assert_eq!(o.status, Status::Internal);
    assert!(o.log.contains("SyntaxError"), "{}", o.log);
    let o = e
        .run(
            &job(
                "export default function main() { throw new Error('boom secret'); }",
                json!({}),
                50_000_000,
            ),
            reads(1),
        )
        .await;
    assert_eq!(o.status, Status::Internal);
    assert!(o.log.contains("boom"));
    // Call cap: two calls with max_calls = 1.
    let o = e
        .run(
            &job(
                "export default function main({busy}) { busy({}); busy({}); return 1; }",
                json!({}),
                50_000_000,
            ),
            reads(1),
        )
        .await;
    assert_eq!(o.status, Status::LimitExceeded, "{}", o.log);
    // Undeclared reads do not exist.
    let o = e
        .run(
            &job(
                "export default function main(r) { return Object.keys(r); }",
                json!({}),
                50_000_000,
            ),
            reads(1),
        )
        .await;
    assert_eq!(result(&o), json!(["busy"]));
    // Columnar access.
    let o = e
        .run(&job("export default function main({busy}) { const t = busy({}); return [t.length, t.col('start_at')[0], t.schema.map(f => f.type)]; }", json!({}), 50_000_000), reads(1))
        .await;
    assert_eq!(
        result(&o),
        json!([3, ms("2026-11-24T10:00:00Z"), ["timestamp", "timestamp"]])
    );
}

/// Python (Monty) engine, same world. Runs when engines/python/dist exists.
#[tokio::test(flavor = "multi_thread")]
async fn python_monty_kernel() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let comp = root.join("engines/python/dist/remit_engine_python.wasm");
    if !comp.exists() {
        eprintln!("skipping: build engines/python first");
        return;
    }
    let e = KernelEngine::new(EngineConfig {
        component: comp,
        cache_dir: Some(root.join("target/remit-engine-cache")),
        pool_instances: 8,
        warm_instances: 2,
        lang: "python/monty".into(),
        ..Default::default()
    })
    .await
    .expect("python engine");
    assert!(e.snapshotted(), "python engine pre-initialized with Wizer");
    let src = r#"
def main(reads, params):
    rows = reads["busy"]({})
    hours = 0
    for r in rows:
        hours = hours + 1
    return {"busy": len(rows), "first": rows[0]["start_at"], "minutes": params["minutes"]}
"#;
    let o = e.run(&job(src, json!({"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 120}), 50_000_000), reads(1)).await;
    let v = result(&o);
    assert_eq!(
        v,
        json!({"busy": 3, "first": "2026-11-24T10:00:00Z", "minutes": 120})
    );
    // Limits apply the same way.
    let o = e
        .run(
            &job(
                "def main(reads, params):\n    while True:\n        pass\n",
                json!({}),
                5_000_000,
            ),
            reads(1),
        )
        .await;
    assert_eq!(o.status, Status::LimitExceeded, "{}", o.log);
    let o = e
        .run(
            &job(
                "def main(reads, params):\n    import os\n    return os.listdir('/')\n",
                json!({}),
                50_000_000,
            ),
            reads(1),
        )
        .await;
    assert_ne!(o.status, Status::Ok, "no filesystem: {}", o.log);
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_built_component() {
    let e = engine().await;
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sender_count.wasm"),
    )
    .unwrap();
    let mut j = job("", json!({}), 50_000_000);
    j.component = true;
    j.source = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
    let o = e.run(&j, reads(1)).await;
    assert_eq!(result(&o), json!(3), "{}", o.log);
    // Structural validation rejects junk and oversize inputs before compiling.
    assert!(crate::sender::validate_structure(b"\0asm junk", &Default::default()).is_err());
    let lim = crate::sender::StructuralLimits {
        max_bytes: 1000,
        ..Default::default()
    };
    assert!(crate::sender::validate_structure(&bytes, &lim)
        .unwrap_err()
        .contains("byte limit"));
    let lim = crate::sender::StructuralLimits {
        max_functions: 3,
        ..Default::default()
    };
    assert!(crate::sender::validate_structure(&bytes, &lim)
        .unwrap_err()
        .contains("functions"));
    // A precompiled artifact (not a component) is refused.
    let mut j2 = j.clone();
    j2.source = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"ELF-or-cwasm");
    assert_eq!(e.run(&j2, reads(1)).await.status, Status::Internal);
}

/// A Wizer image taken after `init()` behaves exactly like running `init()`
/// per instance, and needs no per-instance initialization.
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_matches_init() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mk = |snapshot: bool| {
        let root = root.clone();
        async move {
            KernelEngine::new(EngineConfig {
                component: root.join("engines/js/dist/remit_engine_js.wasm"),
                cache_dir: Some(root.join("target/remit-engine-cache")),
                pool_instances: 8,
                warm_instances: 0,
                snapshot,
                ..Default::default()
            })
            .await
            .expect("engine")
        }
    };
    let (plain, snap) = (mk(false).await, mk(true).await);
    assert!(!plain.snapshotted());
    assert!(snap.snapshotted(), "wizer snapshot of the JS engine");
    let src = r#"export default function main(r, p) {
        const busy = r.busy({}).rows();
        return { n: busy.length, now: Date.now(), r: Math.random(), m: p.minutes, s: JSON.stringify([1, {a: 2}]) };
    }"#;
    let a = result(
        &plain
            .run(&job(src, json!({"minutes": 30}), 50_000_000), reads(1))
            .await,
    );
    let b = result(
        &snap
            .run(&job(src, json!({"minutes": 30}), 50_000_000), reads(1))
            .await,
    );
    assert_eq!(a, b, "snapshot and init() instances agree");
    // Every instance comes fresh from the image: state set by one remit is not
    // visible to the next.
    let leak = r#"export default function main() { const s = globalThis.__seen ?? 0; globalThis.__seen = s + 1; return s; }"#;
    for _ in 0..3 {
        assert_eq!(
            result(&snap.run(&job(leak, json!({}), 50_000_000), reads(1)).await),
            json!(0)
        );
    }
    // Cost of a fresh instance from the image (no pool), vs init() per instance.
    let triv = "export default function main() { return 1; }";
    let time = |e: Arc<KernelEngine>| async move {
        let t = std::time::Instant::now();
        let mut inst = Vec::new();
        for _ in 0..50 {
            let o = e.run(&job(triv, json!({}), 50_000_000), reads(1)).await;
            assert_eq!(o.status, Status::Ok, "{}", o.log);
            inst.push(o.instantiate_us);
        }
        inst.sort();
        (t.elapsed().as_secs_f64() * 1000.0 / 50.0, inst[25])
    };
    let (p_ms, p_inst) = time(plain.clone()).await;
    let (s_ms, s_inst) = time(snap.clone()).await;
    eprintln!("per remit, no pool: init() {p_ms:.3} ms (instantiate+init p50 {p_inst} µs); snapshot {s_ms:.3} ms (instantiate p50 {s_inst} µs)");
    assert!(
        s_inst < p_inst,
        "snapshot instantiation is cheaper than init()"
    );
}

/// The crate carries its own copy of the kernel world so it builds when
/// published; it must stay identical to the normative one in `spec/wit`.
#[test]
fn wit_matches_spec() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let Ok(spec) = std::fs::read_to_string(root.join("../../spec/wit/kernel.wit")) else {
        return; // outside the repository (a packaged crate)
    };
    let ours = std::fs::read_to_string(root.join("wit/kernel.wit")).unwrap();
    assert_eq!(
        ours, spec,
        "crates/remit-kernel/wit/kernel.wit must be a copy of spec/wit/kernel.wit"
    );
}
