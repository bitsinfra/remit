//! `/init` for checking a Linux port inside a throw-away VM (any architecture,
//! emulated or not): runs kernels and prints their metered fuel, then hardens
//! the process and tries to escape.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        println!("vm_selftest FAILED: {e:#}");
    }
    unsafe {
        libc::sync();
    }
}

#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<()> {
    use remit_kernel::{
        encode_params, EngineConfig, KernelEngine, KernelJob, KernelLimits, StaticReads,
    };
    unsafe {
        for (src, dir, ty) in [
            (c"dev", c"/dev", c"devtmpfs"),
            (c"proc", c"/proc", c"proc"),
            (c"tmp", c"/tmp", c"tmpfs"),
        ] {
            libc::mkdir(dir.as_ptr(), 0o755);
            libc::mount(src.as_ptr(), dir.as_ptr(), ty.as_ptr(), 0, std::ptr::null());
        }
    }
    println!("vm_selftest arch={}", std::env::consts::ARCH);
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let cfg = EngineConfig { component: "/engine.wasm".into(), pool_instances: 2, warm_instances: 1, ..Default::default() };
        let e = KernelEngine::new(cfg).await?;
        for src in [
            "export default function main() { return 7; }",
            "export default function main() { let s = 0; for (let i = 0; i < 30000; i++) s = (s + i * 7) | 0; return s; }",
            "export default function main() { let s = 0; for (let i = 1; i < 3000; i++) s += Math.sin(i) / i; return s; }",
            "export default function main() { return [Math.random(), Date.now(), [3,1,2].sort().join()]; }",
        ] {
            let job = KernelJob {
                source: src.into(),
                entry: "main".into(),
                params_cbor: encode_params(&serde_json::Map::new(), &[]),
                nonce: "nonce-123456".into(),
                issued_at_ms: 1_795_000_000_000,
                limits: KernelLimits { fuel: 2_000_000_000, memory_bytes: 64 << 20, wall_ms: 600_000 },
                component: false,
                compiled: None,
            };
            let o = e.run(&job, Box::new(StaticReads { tables: Default::default(), max_calls: Default::default(), calls: Default::default() })).await;
            println!("kernel status={:?} fuel={} result={:?}", o.status, o.fuel_used, o.result_cbor);
        }
        anyhow::Ok(())
    })?;
    let e = remit_kernel::worker::selftest(std::path::Path::new("/engine.wasm"));
    println!("escapes {}", serde_json::to_string(&e)?);
    for t in std::fs::read_dir("/proc/self/task")
        .into_iter()
        .flatten()
        .flatten()
    {
        println!("unexpected: /proc still listable: {:?}", t.path());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
