//! Pre-initialized engine images (Wizer).
//!
//! The Holder snapshots its own, hash-pinned engine component after `init()`
//! (engine realm + prelude) has run with the deterministic `init` stubs: the
//! linear memories and globals are written back into the component as data
//! segments, so every instance starts from that state through Wasmtime's
//! copy-on-write memory images instead of re-running `init`. The snapshot is
//! made from trusted bytes only (never from Sender input), before any remit
//! exists, and each instance still serves exactly one remit.
//!
//! The snapshot keeps the `init` export (the `kernel` world requires it); the
//! Holder never calls it on snapshot instances.

use crate::{build_linker, new_store_with, Ctx, EngineConfig};
use anyhow::anyhow;
use wasmtime::component::{Component, Instance, Lift, WasmList};
use wasmtime::{Config, Engine, Store};
use wasmtime_wizer::ComponentInstanceState;
use wasmtime_wizer::Wizer;

const SNAPSHOT_FUEL: u64 = u64::MAX / 4;

/// Wasmtime config for the snapshotting run: same semantics as the kernel
/// engine (fuel, NaN canonicalization, no GC/memory64/relaxed SIMD), but the
/// on-demand allocator, since this runs once.
fn snapshot_config() -> Config {
    let mut c = Config::new();
    c.wasm_component_model(true);
    c.consume_fuel(true);
    c.epoch_interruption(false);
    c.cranelift_nan_canonicalization(true);
    c.wasm_relaxed_simd(false);
    c.wasm_memory64(false);
    c.wasm_gc(false);
    c.wasm_wide_arithmetic(false);
    c
}

/// Run `init()` on `bytes` and return the pre-initialized component bytes.
pub async fn preinitialize(cfg: &EngineConfig, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut wizer = Wizer::new();
    wizer.init_func("init").keep_init_func(true);
    let (cx, instrumented) = wizer
        .instrument_component(bytes)
        .map_err(|e| anyhow!("wizer instrument: {e}"))?;
    let engine = Engine::new(&snapshot_config())?;
    let component = Component::new(&engine, &instrumented)
        .map_err(|e| anyhow!("compile instrumented engine: {e}"))?;
    let linker = build_linker(&engine)?;
    let (mut store, _stderr) = new_store_with(cfg, &engine);
    store.set_fuel(SNAPSHOT_FUEL)?;
    let instance = linker.instantiate_async(&mut store, &component).await?;
    let init = instance
        .get_typed_func::<(), (Result<(), String>,)>(&mut store, "init")
        .map_err(|e| anyhow!("engine `init` export: {e}"))?;
    let (r,) = init.call_async(&mut store, ()).await?;
    r.map_err(|e| anyhow!("engine init failed: {e}"))?;
    let snap = wizer
        .snapshot_component(
            &cx,
            &mut State {
                store: &mut store,
                instance,
            },
        )
        .await
        .map_err(|e| anyhow!("wizer snapshot: {e}"))?;
    Ok(snap)
}

struct State<'a> {
    store: &'a mut Store<Ctx>,
    instance: Instance,
}

impl State<'_> {
    async fn call<R: Lift + Send + Sync + 'static, R2>(
        &mut self,
        instance: &str,
        func: &str,
        use_ret: impl FnOnce(&mut Store<Ctx>, R) -> R2,
    ) -> R2 {
        let (_, ie) = self
            .instance
            .get_export(&mut *self.store, None, instance)
            .expect("wizer accessor instance");
        let (_, fe) = self
            .instance
            .get_export(&mut *self.store, Some(&ie), func)
            .expect("wizer accessor func");
        let f = self
            .instance
            .get_typed_func::<(), (R,)>(&mut *self.store, fe)
            .expect("wizer accessor type");
        let r = f
            .call_async(&mut *self.store, ())
            .await
            .expect("wizer accessor call")
            .0;

        use_ret(&mut *self.store, r)
    }
}

impl ComponentInstanceState for State<'_> {
    async fn call_func_ret_list_u8(
        &mut self,
        instance: &str,
        func: &str,
        contents: impl FnOnce(&[u8]) + Send,
    ) {
        self.call(instance, func, |store, list: WasmList<u8>| {
            contents(list.as_le_slice(&*store))
        })
        .await
    }
    async fn call_func_ret_s32(&mut self, instance: &str, func: &str) -> i32 {
        self.call(instance, func, |_, r| r).await
    }
    async fn call_func_ret_s64(&mut self, instance: &str, func: &str) -> i64 {
        self.call(instance, func, |_, r| r).await
    }
    async fn call_func_ret_f32(&mut self, instance: &str, func: &str) -> u32 {
        self.call(instance, func, |_, r: f32| r.to_bits()).await
    }
    async fn call_func_ret_f64(&mut self, instance: &str, func: &str) -> u64 {
        self.call(instance, func, |_, r: f64| r.to_bits()).await
    }
}
