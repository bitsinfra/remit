//! Compile the engine for `benches/instructions.rs` outside Valgrind, where it
//! takes seconds instead of the better part of an hour.

fn main() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(remit_kernel::KernelEngine::new(
        remit_kernel::EngineConfig {
            component: format!("{root}/engines/js/dist/remit_engine_js.wasm").into(),
            cache_dir: Some(format!("{root}/target/callgrind-engine-cache").into()),
            baseline_cpu: true,
            pool_instances: 4,
            warm_instances: 1,
            ..Default::default()
        },
    ))
    .unwrap();
}
