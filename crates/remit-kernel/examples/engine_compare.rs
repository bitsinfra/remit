//! Compare `remit:kernel` engine components (for example Boa and an alternative
//! engine) on the same kernels: wall time, fuel and results.
//!   cargo run --release -p remit-kernel --example engine_compare -- boa=a.wasm quickjs=b.wasm

use std::time::Instant;

use remit_kernel::{
    encode_params, EngineConfig, KernelEngine, KernelJob, KernelLimits, StaticReads, Status,
};

const KERNELS: &[(&str, &str)] = &[
    ("trivial", "export default function main() { return 7; }"),
    ("int loop 300k", "export default function main() { let s = 0; for (let i = 0; i < 300000; i++) s = (s + i * 7) | 0; return s; }"),
    ("float loop 300k", "export default function main() { let s = 0; for (let i = 1; i < 300000; i++) s += 1 / i; return Math.round(s * 1e6); }"),
    ("objects 20k", "export default function main() { const a = []; for (let i = 0; i < 20000; i++) a.push({ id: i, k: 'k' + (i % 50), v: i * 2 }); const m = {}; for (const r of a) m[r.k] = (m[r.k] || 0) + r.v; return Object.keys(m).length; }"),
    ("sort 20k", "export default function main() { const a = Array.from({ length: 20000 }, (_, i) => (i * 7919) % 20011); a.sort((x, y) => x - y); return a[100]; }"),
    ("closures", "export default function main() { return Array.from({ length: 20000 }, (_, i) => i).map(x => x * 3).filter(x => x % 2).reduce((a, b) => a + b, 0); }"),
    ("strings", "export default function main() { const p = []; for (let i = 0; i < 10000; i++) p.push('item-' + i); return p.join(',').split(',').map(s => s.length).reduce((a, b) => a + b, 0); }"),
    ("recursion fib 20", "export default function main() { const f = n => n < 2 ? n : f(n - 1) + f(n - 2); return f(20); }"),
];

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    for arg in std::env::args().skip(1) {
        let (name, path) = arg.split_once('=').expect("name=path");
        let cfg = EngineConfig {
            component: path.into(),
            pool_instances: 8,
            ..Default::default()
        };
        let t = Instant::now();
        let e = KernelEngine::new(cfg).await?;
        println!(
            "{name}: {} KiB, cold start {:?}, baseline load fuel {}",
            std::fs::metadata(path)?.len() / 1024,
            t.elapsed(),
            e.baseline_load_fuel()
        );
        for (kernel, src) in KERNELS {
            let job = KernelJob {
                source: (*src).into(),
                entry: "main".into(),
                params_cbor: encode_params(&serde_json::Map::new(), &[]),
                nonce: "nonce-123456".into(),
                issued_at_ms: 1_795_000_000_000,
                limits: KernelLimits {
                    fuel: 20_000_000_000,
                    memory_bytes: 128 << 20,
                    wall_ms: 60_000,
                },
                component: false,
                compiled: None,
            };
            let (mut us, mut fuel, mut result) = (vec![], 0, String::new());
            for _ in 0..15 {
                let o = e
                    .run(
                        &job,
                        Box::new(StaticReads {
                            tables: Default::default(),
                            max_calls: Default::default(),
                            calls: Default::default(),
                        }),
                    )
                    .await;
                assert_eq!(o.status, Status::Ok, "{kernel}: {}", o.log);
                us.push(o.wall_us as f64);
                fuel = o.fuel_used;
                result = format!("{:?}", o.result_cbor);
            }
            println!(
                "  {kernel:18} {:>9.0} us  {fuel:>12} fuel  result {result}",
                median(us)
            );
        }
    }
    Ok(())
}
