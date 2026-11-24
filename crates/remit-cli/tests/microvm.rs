//! Isolation level `microvm` on real KVM. Runs when REMIT_TEST_GUEST_KERNEL
//! names a guest kernel and REMIT_TEST_GUEST_WORKER a `remit-guest` binary.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use remit_kernel::microvm::{prepare, MicroVmConfig};
use remit_kernel::{
    encode_params, ByteBuf, EngineConfig, HostTable, KernelJob, KernelLimits, ReadHost,
    StaticReads, Status, WorkerPool,
};
use remit_read::arrowconv;
use serde_json::{json, Value};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn reads(rows: usize) -> Box<dyn ReadHost> {
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
    let t = HostTable {
        schema_ipc: arrowconv::ipc_schema_message(&b.schema()),
        batches_ipc: vec![ByteBuf(arrowconv::ipc_batch_message(&b))],
        rows: rows as u64,
        bytes: b.get_array_memory_size() as u64,
    };
    Box::new(StaticReads {
        tables: BTreeMap::from([("t".to_string(), t)]),
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
async fn kernels_run_in_a_microvm() {
    let (Ok(kernel), Ok(worker)) = (
        std::env::var("REMIT_TEST_GUEST_KERNEL"),
        std::env::var("REMIT_TEST_GUEST_WORKER"),
    ) else {
        eprintln!("skipping: REMIT_TEST_GUEST_KERNEL / REMIT_TEST_GUEST_WORKER not set");
        return;
    };
    let engine = root().join("engines/js/dist/remit_engine_js.wasm");
    let dir = std::env::temp_dir().join(format!("remit-microvm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = MicroVmConfig {
        kernel: kernel.into(),
        worker: Some(worker.into()),
        ..Default::default()
    };
    let ec = EngineConfig {
        component: engine.clone(),
        ..Default::default()
    };
    let (vmm, args) = prepare(&cfg, ec, &dir).await.unwrap();
    let vm = WorkerPool::microvm(vmm, args, 1);
    let t = std::time::Instant::now();
    vm.warm("a").await.unwrap();
    eprintln!("guest ready in {:?}", t.elapsed());

    // Same results and the same metered fuel as a worker process.
    let sha = remit_wire::sha256_hex(&std::fs::read(&engine).unwrap());
    let cache = root().join("target/remit-engine-cache");
    let wargs = [
        "kernel-worker",
        "--engine",
        engine.to_str().unwrap(),
        "--sha256",
        &sha,
        "--cache-dir",
        cache.to_str().unwrap(),
    ];
    let proc: Arc<WorkerPool> = WorkerPool::new(
        PathBuf::from(env!("CARGO_BIN_EXE_remit")),
        wargs.map(String::from).to_vec(),
        1,
    );
    for (src, n) in [
        ("export default function main() { return 7; }", 1),
        ("export default function main({ t }) { let s = 0; for (let i = 0; i < 3; i++) s += t({}).rows().reduce((a, r) => a + r.id, 0); return s; }", 1000),
        ("export default function main({ t }) { return t({}).rows().slice(0, 3).map(r => r.name); }", 50_000),
        ("export default function main() { return [Math.random(), Date.now()]; }", 1),
    ] {
        let a = vm.run("a", &job(src, 4_000_000_000), reads(n)).await;
        let b = proc.run("a", &job(src, 4_000_000_000), reads(n)).await;
        assert_eq!(value(&a), value(&b), "{src}");
        assert_eq!(a.fuel_used, b.fuel_used, "{src}");
    }

    // Adversarial kernels are contained and the guest keeps serving.
    for src in [
        "export default function main() { for (;;) {} }",
        "export default function main() { const a = []; for (;;) a.push(new Uint8Array(1 << 24)); }",
        "export default function main() { const f = () => f() + 1; return f(); }",
        "export default function main() { return 'x'.repeat(1 << 29); }",
    ] {
        assert_ne!(vm.run("a", &job(src, 200_000_000), reads(1)).await.status, Status::Ok, "{src}");
        assert_eq!(value(&vm.run("a", &job("export default function main() { return 7; }", 50_000_000), reads(1)).await), json!(7));
    }

    // One VM per trust domain, with no network device and no disk.
    vm.warm("b").await.unwrap();
    let (a, b) = (
        vm.worker_pid("a").await.unwrap(),
        vm.worker_pid("b").await.unwrap(),
    );
    assert_ne!(a, b);
    for pid in [a, b] {
        let cmd = String::from_utf8_lossy(&std::fs::read(format!("/proc/{pid}/cmdline")).unwrap())
            .replace('\0', " ");
        assert!(
            cmd.contains("-accel kvm") && cmd.contains("-nodefaults") && !cmd.contains("-net"),
            "{cmd}"
        );
        let kvm = std::fs::read_dir(format!("/proc/{pid}/fd")).map(|d| {
            d.flatten().any(|f| {
                std::fs::read_link(f.path()).is_ok_and(|l| l.to_string_lossy().contains("kvm-vm"))
            })
        });
        assert!(kvm.unwrap_or(true), "a real KVM VM");
    }
    // Warm round trip.
    let t = std::time::Instant::now();
    for _ in 0..50 {
        value(
            &vm.run(
                "a",
                &job("export default function main() { return 1; }", 50_000_000),
                reads(1),
            )
            .await,
        );
    }
    eprintln!("warm run: {:?}", t.elapsed() / 50);
    // A dead guest is replaced.
    unsafe { libc::kill(a as i32, libc::SIGKILL) };
    let _ = vm
        .run(
            "a",
            &job("export default function main() { return 1; }", 50_000_000),
            reads(1),
        )
        .await;
    assert_eq!(
        value(
            &vm.run(
                "a",
                &job("export default function main() { return 8; }", 50_000_000),
                reads(1)
            )
            .await
        ),
        json!(8)
    );
    drop(vm);
    let _ = std::fs::remove_dir_all(&dir);
}
