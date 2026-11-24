//! Isolation level `process` against the real worker binary: shared-memory
//! handoff, the compile worker, and adversarial kernels (escape attempts, fuel
//! evasion, memory storms, compile bombs, Spectre gadgets).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use remit_kernel::{
    encode_params, ByteBuf, HostTable, KernelJob, KernelLimits, ReadHost, StaticReads, Status,
    WorkerPool,
};
use remit_read::arrowconv;
use serde_json::{json, Value};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn pool() -> Arc<WorkerPool> {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_remit"));
    let engine = root().join("engines/js/dist/remit_engine_js.wasm");
    let sha = remit_wire::sha256_hex(&std::fs::read(&engine).unwrap());
    let cache = root().join("target/remit-engine-cache");
    let args = [
        "kernel-worker",
        "--engine",
        engine.to_str().unwrap(),
        "--sha256",
        &sha,
        "--cache-dir",
        cache.to_str().unwrap(),
    ];
    let compile = (bin.clone(), vec!["compile-worker".to_string()]);
    WorkerPool::with_compiler(bin, args.map(String::from).to_vec(), 1, Some(compile))
}

fn table(rows: usize) -> HostTable {
    let data: Vec<Value> = (0..rows)
        .map(|i| json!({"id": i, "name": format!("row-{i}")}))
        .collect();
    let b = arrowconv::rows_to_batch(
        &data,
        &[
            ("id".into(), "int".into()),
            ("name".into(), "string".into()),
        ],
    );
    HostTable {
        schema_ipc: arrowconv::ipc_schema_message(&b.schema()),
        batches_ipc: vec![ByteBuf(arrowconv::ipc_batch_message(&b))],
        rows: rows as u64,
        bytes: b.get_array_memory_size() as u64,
    }
}

fn reads(rows: usize) -> Box<dyn ReadHost> {
    Box::new(StaticReads {
        tables: BTreeMap::from([("t".to_string(), table(rows))]),
        max_calls: BTreeMap::from([("t".to_string(), 100)]),
        calls: BTreeMap::new(),
    })
}

fn job(src: &str, fuel: u64) -> KernelJob {
    KernelJob {
        source: src.into(),
        entry: "main".into(),
        params_cbor: encode_params(&serde_json::Map::new(), &[]),
        nonce: "nonce-123456".into(),
        issued_at_ms: 1_795_000_000_000,
        limits: KernelLimits {
            fuel,
            memory_bytes: 64 << 20,
            wall_ms: 20_000,
        },
        component: false,
        compiled: None,
    }
}

fn value(o: &remit_kernel::KernelOutcome) -> Value {
    assert_eq!(o.status, Status::Ok, "{}", o.log);
    remit_emit::decode_kernel(&o.result_cbor).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn shared_memory_and_inline_handoff() {
    let p = pool();
    let sum = "export default function main({ t }) { let s = 0; for (let i = 0; i < 3; i++) s += t({}).rows().reduce((a, r) => a + r.id, 0); return s; }";
    let o = p.run("d1", &job(sum, 2_000_000_000), reads(1000)).await;
    assert_eq!(value(&o), json!(3 * 999 * 1000 / 2));
    // A table larger than the ring falls back to inline frames.
    let big = "export default function main({ t }) { return t({}).length; }";
    let mut j = job(big, 8_000_000_000);
    j.limits.memory_bytes = 256 << 20;
    j.limits.wall_ms = 60_000;
    let o = p.run("d1", &j, reads(700_000)).await;
    assert_eq!(value(&o), json!(700_000), "{}", o.log);
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_components_go_through_the_compile_worker() {
    let p = pool();
    let wasm =
        std::fs::read(root().join("crates/remit-kernel/tests/fixtures/sender_count.wasm")).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&wasm);
    let mut j = job(&b64, 500_000_000);
    j.component = true;
    for _ in 0..2 {
        // Second run: cached artifact.
        let o = p.run("d2", &j, reads(7)).await;
        assert_ne!(o.status, Status::Internal, "{}", o.log);
    }
    // Not wasm, oversized, or bomb-shaped inputs fail closed.
    for bad in [b"not wasm".to_vec(), vec![0u8; 9 << 20], bomb()] {
        let mut j = j.clone();
        j.source = base64::engine::general_purpose::STANDARD.encode(bad);
        let t = std::time::Instant::now();
        let o = p.run("d2", &j, reads(1)).await;
        assert_eq!(o.status, Status::Internal);
        assert!(t.elapsed().as_secs() < 30);
    }
}

/// A component whose core module has far more functions than the limit.
fn bomb() -> Vec<u8> {
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    let n: u32 = 60_000;
    let leb = |mut v: u32| {
        let mut o = vec![];
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                o.push(b);
                break o;
            }
            o.push(b | 0x80);
        }
    };
    let mut sec = |id: u8, body: Vec<u8>| {
        m.push(id);
        m.extend(leb(body.len() as u32));
        m.extend(body);
    };
    sec(1, vec![1, 0x60, 0, 0]);
    let mut f = leb(n);
    f.extend(std::iter::repeat_n(0u8, n as usize));
    sec(3, f);
    let mut c = leb(n);
    for _ in 0..n {
        c.extend([2, 0, 0x0b]);
    }
    sec(10, c);
    // Wrap in a component with one core module section.
    let mut comp = b"\0asm\x0d\0\x01\0".to_vec();
    comp.push(1);
    comp.extend(leb(m.len() as u32));
    comp.extend(m);
    comp
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_kernels_are_contained() {
    let p = pool();
    // Ambient authority does not exist.
    let probe = r#"export default function main() {
        const names = ["fetch","XMLHttpRequest","WebSocket","require","process","Deno","Bun","setTimeout","setInterval","WebAssembly","SharedArrayBuffer","Atomics","performance","__remit_call","__remit_fn","__remit_col","__remit_declared"];
        return names.filter(n => { try { return typeof globalThis[n] !== "undefined" && !["SharedArrayBuffer","Atomics"].includes(n); } catch { return true; } });
    }"#;
    assert_eq!(
        value(&p.run("adv", &job(probe, 50_000_000), reads(1)).await),
        json!([])
    );
    // Dynamic code still runs inside the same sandbox with the same imports.
    let dynamic = r#"export default function main() { try { return String(new Function("return typeof fetch")()); } catch (e) { return "blocked"; } }"#;
    assert!(["undefined", "blocked"].contains(
        &value(&p.run("adv", &job(dynamic, 50_000_000), reads(1)).await)
            .as_str()
            .unwrap()
    ));
    let cases: &[(&str, &str)] = &[
        ("busy loop", "export default function main() { for (;;) {} }"),
        ("recursion", "export default function main() { const f = n => 1 + f(n + 1); return f(0); }"),
        ("regex backtracking", "export default function main() { return /^(a+)+$/.test('a'.repeat(40) + '!'); }"),
        ("string doubling", "export default function main() { let s = 'x'; for (;;) s += s; }"),
        ("array storm", "export default function main() { const a = []; for (;;) a.push(new Array(1e5).fill(1)); }"),
        ("typed array storm", "export default function main() { const a = []; for (;;) a.push(new Uint8Array(1 << 24)); }"),
        ("sort comparator", "export default function main() { return Array.from({ length: 1e7 }, (_, i) => i).sort(() => Math.random() - 0.5).length; }"),
        ("bigint", "export default function main() { let x = 3n; for (;;) x = x * x; }"),
        ("json nesting", "export default function main() { let s = '['.repeat(1e6); return JSON.parse(s); }"),
        ("promise flood", "export default async function main() { const f = async () => { await null; return f(); }; return f(); }"),
        ("getter bomb", "export default function main() { const o = {}; Object.defineProperty(o, 'x', { enumerable: true, get() { for (;;) {} } }); return o; }"),
        ("cyclic result", "export default function main() { const o = {}; o.o = o; return o; }"),
        ("deep result", "export default function main() { let o = {}; for (let i = 0; i < 1e5; i++) o = { o }; return o; }"),
    ];
    for (name, src) in cases {
        let t = std::time::Instant::now();
        let o = p.run("adv", &job(src, 200_000_000), reads(1)).await;
        assert_ne!(o.status, Status::Ok, "{name}");
        assert!(t.elapsed().as_secs() < 25, "{name} took {:?}", t.elapsed());
        // The trust domain keeps working (trapped stores are never reused).
        let ok = p
            .run(
                "adv",
                &job("export default function main() { return 7; }", 50_000_000),
                reads(1),
            )
            .await;
        assert_eq!(value(&ok), json!(7), "after {name}");
    }
}

/// Spectre gadgets need a timer, shared memory or threads to observe the cache.
/// None exists; and a worker holds only its own trust domain's data.
#[tokio::test(flavor = "multi_thread")]
async fn spectre_gadgets_have_no_clock_and_nothing_to_leak() {
    let p = pool();
    let gadget = r#"export default function main({ t }) {
        const probe = new Uint8Array(256 * 4096), arr = new Uint8Array(16);
        const clocks = () => [Date.now(), new Date().getTime(), typeof performance === "object" ? performance.now() : 0];
        const before = clocks();
        let junk = 0;
        for (let i = 0; i < 20000; i++) {
            const x = i % 64 === 63 ? 1 << 20 : i % 16;          // mistrain, then out of bounds
            if (x < arr.length) junk ^= probe[arr[x] * 4096];
        }
        const deltas = [];
        for (let g = 0; g < 256; g++) { const a = clocks(); junk ^= probe[g * 4096]; const b = clocks(); deltas.push(b.map((v, i) => v - a[i]).reduce((p, c) => p + c, 0)); }
        const after = clocks();
        return { moved: deltas.some(d => d !== 0) || before.some((v, i) => v !== after[i]), junk: junk === -1 };
    }"#;
    let o = p
        .run("spectre", &job(gadget, 4_000_000_000), reads(1))
        .await;
    assert_eq!(
        value(&o),
        json!({"moved": false, "junk": false}),
        "every clock is frozen"
    );
    // Two trust domains never share a process.
    assert_ne!(p.worker_pid("spectre").await, p.worker_pid("adv2").await);
    let _ = p
        .run(
            "adv2",
            &job("export default function main() { return 1; }", 50_000_000),
            reads(1),
        )
        .await;
    let (a, b) = (p.worker_pid("spectre").await, p.worker_pid("adv2").await);
    assert!(a.is_some() && b.is_some() && a != b);
    // The worker's environment is empty and its secrets do not exist.
    #[cfg(target_os = "linux")]
    {
        let env = std::fs::read(format!("/proc/{}/environ", a.unwrap())).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&env).contains("PATH="));
        // Every thread is confined, not just the one that applied the filter.
        let tasks: Vec<_> = std::fs::read_dir(format!("/proc/{}/task", a.unwrap()))
            .unwrap()
            .flatten()
            .collect();
        assert!(tasks.len() > 1);
        for t in tasks {
            let st = std::fs::read_to_string(t.path().join("status")).unwrap();
            assert!(
                st.contains("Seccomp:\t2") && st.contains("NoNewPrivs:\t1"),
                "unconfined thread: {st}"
            );
        }
    }
}

/// The OS layer, on its own: harden like a worker and try to break out.
#[test]
fn hardened_process_cannot_escape() {
    let secret = root().join("Cargo.toml");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_remit"))
        .arg("worker-selftest")
        .arg(&secret)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let e: remit_kernel::worker::Escapes = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        e,
        Default::default(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
