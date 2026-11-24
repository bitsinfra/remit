//! `remit bench`: measure the performance targets on this machine against an
//! in-process Holder with synthetic data.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use datafusion::arrow::array::{Float64Array, StringArray, TimestampMillisecondArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use remit_holder::admission::{admit, AdmitOptions, Outcome};
use remit_read::ResourceConfig;
use remit_wire::Signer;
use serde_json::{json, Value};

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return 0.0;
    }
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn data() -> (Arc<Schema>, RecordBatch, Arc<Schema>, RecordBatch) {
    let n = 10_000;
    let regions = ["EMEA", "AMER", "APAC", "LATAM"];
    let s1 = Arc::new(Schema::new(vec![
        Field::new("account_id", DataType::Utf8, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("arr", DataType::Float64, false),
    ]));
    let b1 = RecordBatch::try_new(
        s1.clone(),
        vec![
            Arc::new(StringArray::from(
                (0..n).map(|i| format!("a{i}")).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                (0..n).map(|i| regions[i % 4]).collect::<Vec<_>>(),
            )),
            Arc::new(Float64Array::from(
                (0..n).map(|i| (i % 997) as f64 * 100.0).collect::<Vec<_>>(),
            )),
        ],
    )
    .unwrap();
    let base = 1_795_500_000_000i64;
    let ts = DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()));
    let s2 = Arc::new(Schema::new(vec![
        Field::new("start_at", ts.clone(), false),
        Field::new("end_at", ts, false),
        Field::new("status", DataType::Utf8, false),
    ]));
    let m = 400;
    let b2 = RecordBatch::try_new(
        s2.clone(),
        vec![
            Arc::new(
                TimestampMillisecondArray::from(
                    (0..m)
                        .map(|i| base + i as i64 * 3_600_000 * 7)
                        .collect::<Vec<_>>(),
                )
                .with_timezone("UTC"),
            ),
            Arc::new(
                TimestampMillisecondArray::from(
                    (0..m)
                        .map(|i| base + i as i64 * 3_600_000 * 7 + 3_600_000)
                        .collect::<Vec<_>>(),
                )
                .with_timezone("UTC"),
            ),
            Arc::new(StringArray::from(
                (0..m)
                    .map(|i| if i % 9 == 0 { "cancelled" } else { "confirmed" })
                    .collect::<Vec<_>>(),
            )),
        ],
    )
    .unwrap();
    (s1, b1, s2, b2)
}

fn manifest(
    holder: &str,
    sender: &Signer,
    mode: &str,
    sql: &str,
    source: Option<&str>,
    returns: Value,
    nonce: u64,
) -> remit_wire::Envelope {
    let now = chrono::Utc::now();
    let mut m = json!({
        "remit": "0.1", "sender": sender.id(), "holder": holder,
        "issued_at": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expires_at": (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "nonce": format!("bench-{nonce:016x}"), "purpose": "analytics", "mode": mode,
        "reads": {"q": {"sql": sql, "max_rows": 1000}}, "params": {}, "limits": {"fuel": 50_000_000, "wall_ms": 5000},
        "returns": returns,
    });
    if let Some(src) = source {
        m["code"] = json!({"lang": "js/es2023", "entry": "main", "source": src, "source_sha256": remit_wire::sha256_hex(src.as_bytes())});
    }
    remit_wire::sign_manifest(&remit_wire::Manifest::from_value(m).unwrap(), sender)
}

pub async fn run(engine: &Path, iterations: usize, as_json: bool) -> anyhow::Result<()> {
    let (s1, b1, s2, b2) = data();
    let sender = Signer::generate(None);
    let sender_id = sender.id().to_string();
    let dir = std::env::temp_dir().join(format!("remit-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let holder_id = "did:web:bench.example";
    let h = remit_holder::Holder::builder(holder_id)
        .engine(engine.to_path_buf())
        .config(|c| {
            c.holder.data_dir = dir.display().to_string();
            c.budgets.bits_per_principal_per_day = u64::MAX / 4;
            c.budgets.bits_global_per_day = u64::MAX / 4;
            c.budgets.fuel_per_principal_per_minute = u64::MAX / 4;
            c.budgets.fuel_per_principal_per_day = u64::MAX / 4;
            c.budgets.concurrency_per_principal = 1024;
        })
        .source_batches("crm.accounts", s1.clone(), vec![b1.clone()])
        .resource(
            "crm.accounts",
            ResourceConfig {
                aggregate_only: true,
                k: Some(5),
                privacy_unit: Some("account_id".into()),
                ..Default::default()
            },
        )
        .source_batches("calendar.events", s2, vec![b2])
        .resource("calendar.events", ResourceConfig::default())
        .presets(["aggregate-only", "internal-trusted"])
        .config(move |c| {
            c.policy.presets.push("personal-vault".into());
            c.principals.push(remit_holder::config::PrincipalSection {
                id: sender_id,
                groups: vec!["internal".into(), "verified-agents".into()],
                verified: true,
                ..Default::default()
            });
        })
        .build()
        .await?;
    let kernel = !matches!(h.isolation, remit_holder::state::Isolation::None);
    let qsql = "SELECT region, SUM(arr) AS arr, COUNT(*) AS n FROM crm.accounts GROUP BY region";
    let qret = json!({"list": {"max": 10, "of": {"struct": {"region": {"string": {"max_len": 8}}, "arr": {"float": {"min": 0, "max": 1e12, "precision": 1}}, "n": {"int": {"min": 0, "max": 100000}}}}}});
    let mut nonce = 0u64;
    let mut next = || {
        nonce += 1;
        nonce
    };
    let warm = iterations.min(50);
    // 1. Admission, cached plan.
    let envs: Vec<Vec<u8>> = (0..iterations + warm)
        .map(|_| {
            serde_json::to_vec(&manifest(
                holder_id,
                &sender,
                "query",
                qsql,
                None,
                qret.clone(),
                next(),
            ))
            .unwrap()
        })
        .collect();
    let mut cached = Vec::new();
    for (i, e) in envs.iter().enumerate() {
        let t = Instant::now();
        let o = admit(
            &h,
            e,
            AdmitOptions {
                dry: true,
                ..Default::default()
            },
        )
        .await;
        let us = t.elapsed().as_secs_f64() * 1e6;
        if !matches!(o, Outcome::Admitted(_)) {
            let (_, v) = remit_holder::http::outcome_json(&h, &o);
            anyhow::bail!("bench remit not admitted: {v}");
        }
        if i >= warm {
            cached.push(us);
        }
    }
    // 2. Admission, cold analyze (unique programs).
    let cold_n = (iterations / 10).max(20);
    let cold_envs: Vec<Vec<u8>> = (0..cold_n)
        .map(|i| {
            let sql = format!("SELECT region, SUM(arr) AS arr, COUNT(*) AS n FROM crm.accounts WHERE arr >= {i} GROUP BY region");
            serde_json::to_vec(&manifest(holder_id, &sender, "query", &sql, None, qret.clone(), next())).unwrap()
        })
        .collect();
    let mut cold = Vec::new();
    for e in &cold_envs {
        let t = Instant::now();
        let _ = admit(
            &h,
            e,
            AdmitOptions {
                dry: true,
                ..Default::default()
            },
        )
        .await;
        cold.push(t.elapsed().as_secs_f64() * 1e6);
    }
    // 3. Query-mode overhead over raw DataFusion.
    let ctx = SessionContext::new();
    ctx.register_table("accounts", Arc::new(MemTable::try_new(s1, vec![vec![b1]])?))?;
    let raw_sql = "SELECT region, SUM(arr) AS arr, COUNT(*) AS n FROM accounts GROUP BY region";
    let qn = (iterations / 4).max(50);
    let mut raw = Vec::new();
    for _ in 0..qn {
        let t = Instant::now();
        let _ = ctx.sql(raw_sql).await?.collect().await?;
        raw.push(t.elapsed().as_secs_f64() * 1e6);
    }
    let mut remit_q = Vec::new();
    for i in 0..qn {
        // Distinct params_sha avoids the result cache: vary nothing but the nonce
        // and bypass the cache by clearing it.
        h.result_cache.lock().clear();
        let e = serde_json::to_vec(&manifest(
            holder_id,
            &sender,
            "query",
            qsql,
            None,
            qret.clone(),
            next(),
        ))
        .unwrap();
        let t = Instant::now();
        let o = admit(
            &h,
            &e,
            AdmitOptions {
                dry: false,
                ..Default::default()
            },
        )
        .await;
        match o {
            Outcome::Admitted(a) => {
                let r = remit_holder::run::execute(&h, *a, format!("bench{i}")).await;
                anyhow::ensure!(r.status == "ok", "query run failed: {}", r.status);
            }
            o => anyhow::bail!(
                "query remit not admitted: {}",
                remit_holder::http::outcome_json(&h, &o).1
            ),
        }
        remit_q.push(t.elapsed().as_secs_f64() * 1e6);
    }
    let q_over = pct(&mut remit_q.clone(), 0.5) - pct(&mut raw.clone(), 0.5);
    let q_over99 = pct(&mut remit_q.clone(), 0.99) - pct(&mut raw.clone(), 0.99);
    // 6. Throughput, cached trivial query (result cache allowed).
    let tn = (iterations / 2).max(100);
    let tenvs: Vec<Vec<u8>> = (0..tn)
        .map(|_| {
            serde_json::to_vec(&manifest(
                holder_id,
                &sender,
                "query",
                qsql,
                None,
                qret.clone(),
                next(),
            ))
            .unwrap()
        })
        .collect();
    let t = Instant::now();
    for (i, e) in tenvs.iter().enumerate() {
        match admit(
            &h,
            e,
            AdmitOptions {
                dry: false,
                ..Default::default()
            },
        )
        .await
        {
            Outcome::Admitted(a) => {
                let r = remit_holder::run::execute(&h, *a, format!("tq{i}")).await;
                anyhow::ensure!(r.status == "ok", "query run failed: {}", r.status);
            }
            o => anyhow::bail!(
                "throughput remit not admitted: {}",
                remit_holder::http::outcome_json(&h, &o).1
            ),
        }
    }
    let q_tput = tn as f64 / t.elapsed().as_secs_f64();
    // Kernel paths.
    let mut k_inst = Vec::new();
    let mut k_fixed = Vec::new();
    let mut k_tput = 0.0;
    if kernel {
        let src = "export default function main() { return 1; }";
        let ksql = "SELECT start_at, end_at FROM calendar.events WHERE status <> 'cancelled'";
        let kret = json!({"int": {"min": 0, "max": 1}});
        let kn = (iterations / 10).max(30);
        let mut engine_inst = Vec::new();
        if let Some(remit_holder::state::EngineHandle::InProcess(e)) = h.engine("js/es2023") {
            for i in 0..kn + 20 {
                let job = remit_kernel::KernelJob {
                    source: src.into(),
                    entry: "main".into(),
                    params_cbor: remit_kernel::encode_params(&serde_json::Map::new(), &[]),
                    nonce: "bench-nonce".into(),
                    issued_at_ms: 0,
                    limits: remit_kernel::KernelLimits {
                        fuel: 10_000_000,
                        memory_bytes: 64 << 20,
                        wall_ms: 5000,
                    },
                    component: false,
                    compiled: None,
                };
                let reads = remit_kernel::StaticReads {
                    tables: Default::default(),
                    max_calls: Default::default(),
                    calls: Default::default(),
                };
                let o = e.run(&job, Box::new(reads)).await;
                anyhow::ensure!(
                    o.status == remit_kernel::Status::Ok,
                    "trivial kernel failed: {}",
                    o.log
                );
                if i >= 20 {
                    engine_inst.push(o.instantiate_us as f64);
                    k_fixed.push(o.wall_us as f64);
                }
                // Let the pool refill between samples (steady state, not burst).
                tokio::time::sleep(std::time::Duration::from_millis(3)).await;
            }
        }
        k_inst = engine_inst;
        let t = Instant::now();
        for i in 0..kn {
            h.result_cache.lock().clear();
            let e = serde_json::to_vec(&manifest(
                holder_id,
                &sender,
                "kernel",
                ksql,
                Some(src),
                kret.clone(),
                next(),
            ))
            .unwrap();
            match admit(
                &h,
                &e,
                AdmitOptions {
                    dry: false,
                    ..Default::default()
                },
            )
            .await
            {
                Outcome::Admitted(a) => {
                    let r = remit_holder::run::execute(&h, *a, format!("tk{i}")).await;
                    anyhow::ensure!(r.status == "ok", "kernel run failed: {}", r.status);
                }
                o => anyhow::bail!(
                    "kernel remit not admitted: {}",
                    remit_holder::http::outcome_json(&h, &o).1
                ),
            }
        }
        k_tput = kn as f64 / t.elapsed().as_secs_f64();
    }
    let ms = |us: f64| us / 1000.0;
    let rows = vec![
        (
            "Admission, cached plan",
            ms(pct(&mut cached.clone(), 0.5)),
            ms(pct(&mut cached, 0.99)),
            "≤ 0.15 ms / ≤ 1 ms",
        ),
        (
            "Admission, cold analyze",
            ms(pct(&mut cold.clone(), 0.5)),
            ms(pct(&mut cold, 0.99)),
            "≤ 1 ms / ≤ 5 ms",
        ),
        (
            "Query-mode overhead vs raw DataFusion",
            ms(q_over),
            ms(q_over99),
            "≤ 0.5 ms / ≤ 2 ms",
        ),
        (
            "Kernel instantiate (pooled)",
            ms(pct(&mut k_inst.clone(), 0.5)),
            ms(pct(&mut k_inst, 0.99)),
            "≤ 0.05 ms / ≤ 0.5 ms",
        ),
        (
            "Kernel fixed overhead (trivial kernel)",
            ms(pct(&mut k_fixed.clone(), 0.5)),
            ms(pct(&mut k_fixed, 0.99)),
            "≤ 1 ms / ≤ 5 ms",
        ),
    ];
    let report = json!({
        "machine": {"arch": std::env::consts::ARCH, "os": std::env::consts::OS, "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)},
        "latency_ms": rows.iter().map(|(n, p50, p99, t)| json!({"path": n, "p50": (p50 * 1000.0).round() / 1000.0, "p99": (p99 * 1000.0).round() / 1000.0, "target": t})).collect::<Vec<_>>(),
        "throughput_per_s": {"query_cached": q_tput.round(), "query_target": 2000, "kernel_trivial": k_tput.round(), "kernel_target": 1000},
        "raw_datafusion_p50_ms": ms(pct(&mut raw, 0.5)),
        "kernel_enabled": kernel,
    });
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "remit bench ({} {}, {} cpus) — {} iterations",
            std::env::consts::OS,
            std::env::consts::ARCH,
            report["machine"]["cpus"],
            iterations
        );
        println!(
            "{:<42} {:>10} {:>10}   target p50 / p99",
            "path", "p50 ms", "p99 ms"
        );
        for (n, p50, p99, t) in &rows {
            println!("{n:<42} {p50:>10.3} {p99:>10.3}   {t}");
        }
        println!(
            "{:<42} {:>10.0} /s   target ≥ 2000/s",
            "Throughput, trivial query (cached)", q_tput
        );
        if kernel {
            println!(
                "{:<42} {:>10.0} /s   target ≥ 1000/s",
                "Throughput, trivial kernels", k_tput
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Measure ns per unit of fuel for the JS engine on this machine: pure compute
/// and allocation-heavy kernels, best of several runs.
pub async fn calibrate(engine: &Path) -> anyhow::Result<()> {
    let e = remit_kernel::KernelEngine::new(remit_kernel::EngineConfig {
        component: engine.to_path_buf(),
        ..Default::default()
    })
    .await?;
    let kernels = [
        ("compute", "export default function main() { let s = 0; for (let i = 0; i < 400000; i++) s = (s * 31 + i) % 1000003; return s; }"),
        ("objects", "export default function main() { const m = new Map(); for (let i = 0; i < 60000; i++) m.set('k' + (i % 997), { i }); return m.size; }"),
        ("arrays", "export default function main() { const a = Array.from({ length: 40000 }, (_, i) => (i * 7919) % 10007); a.sort((x, y) => x - y); return a[5]; }"),
    ];
    let mut out = Vec::new();
    for (name, src) in kernels {
        let mut best = f64::INFINITY;
        let mut fuel = 0;
        for i in 0..9 {
            let job = remit_kernel::KernelJob {
                source: src.into(),
                entry: "main".into(),
                params_cbor: remit_kernel::encode_params(&serde_json::Map::new(), &[]),
                nonce: "calibration".into(),
                issued_at_ms: 0,
                limits: remit_kernel::KernelLimits {
                    fuel: 50_000_000_000,
                    memory_bytes: 128 << 20,
                    wall_ms: 60_000,
                },
                component: false,
                compiled: None,
            };
            let reads = remit_kernel::StaticReads {
                tables: Default::default(),
                max_calls: Default::default(),
                calls: Default::default(),
            };
            let o = e.run(&job, Box::new(reads)).await;
            anyhow::ensure!(o.status == remit_kernel::Status::Ok, "{name}: {}", o.log);
            anyhow::ensure!(i == 0 || fuel == o.fuel_used, "fuel must be deterministic");
            fuel = o.fuel_used;
            best = best.min((o.wall_us - o.instantiate_us) as f64 * 1000.0);
        }
        println!(
            "{name:<10} fuel {fuel:>12}  best {:>8.2} ms  {:.3} ns/fuel",
            best / 1e6,
            best / fuel as f64
        );
        out.push(best / fuel as f64);
    }
    let mean = out.iter().sum::<f64>() / out.len() as f64;
    println!(
        "calibration.in entry: (\"boa\", \"{}-{}\", {mean:.3})",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    Ok(())
}
