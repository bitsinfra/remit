//! Sender-built Wasm component kernels (`lang = "wasm/component"`).
//!
//! * The Sender ships the component *bytes* (base64 in `code.source`, bound
//!   by `source_sha256`). **Precompiled `.cwasm` is never accepted.**
//! * Structural validation first (NEAR-style limits): size, functions, code
//!   and data bytes, memories, tables, nested modules, and an import allowlist
//!   (`remit:kernel/*` plus the deterministic WASI stub set — no sockets, no
//!   HTTP, no filesystem beyond the empty preopen set).
//! * Compiled by the Holder with a **restricted engine** (SIMD, relaxed SIMD,
//!   GC, memory64, multi-memory, tail calls, exceptions off; NaN
//!   canonicalization, fuel) on a blocking thread under a compile timeout;
//!   cached by hash. In `process` isolation this happens inside the
//!   per-trust-domain worker.
//! * Runs the `sender-kernel` world: one `run(params) -> result` export, the
//!   same `data` / `holder-fns` host implementation, the same fuel pricing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use base64::Engine as _;
use wasmtime::component::Component;
use wasmtime::wasmparser::{Parser, Payload, Validator, WasmFeatures};
use wasmtime::{Config, Engine, InstanceAllocationStrategy};

use crate::{
    build_linker, EngineConfig, KernelEngine, KernelJob, KernelOutcome, Limiter, ReadHost, Status,
};

pub(crate) mod sbindings {
    wasmtime::component::bindgen!({
        // A copy of spec/wit, kept identical by `wit_matches_spec`.
        path: "wit",
        world: "sender-kernel",
        imports: { default: async | trappable },
        exports: { default: async },
        with: {
            "remit:kernel/data": crate::bindings::remit::kernel::data,
            "remit:kernel/holder-fns": crate::bindings::remit::kernel::holder_fns,
        },
    });
}

/// NEAR-style structural limits.
#[derive(Clone, Debug)]
pub struct StructuralLimits {
    pub max_bytes: usize,
    pub max_functions: u32,
    pub max_code_bytes: usize,
    pub max_data_bytes: usize,
    pub max_memories: u32,
    pub max_tables: u32,
    pub max_core_modules: u32,
    pub max_imports: u32,
}

impl Default for StructuralLimits {
    fn default() -> Self {
        StructuralLimits {
            max_bytes: 8 << 20,
            max_functions: 50_000,
            max_code_bytes: 6 << 20,
            max_data_bytes: 4 << 20,
            max_memories: 4,
            max_tables: 16,
            max_core_modules: 16,
            max_imports: 128,
        }
    }
}

/// Import namespaces a Sender component may reference.
const ALLOWED_IMPORT_PREFIXES: &[&str] = &[
    "remit:kernel/data",
    "remit:kernel/holder-fns",
    "wasi:cli/environment",
    "wasi:cli/exit",
    "wasi:cli/stdin",
    "wasi:cli/stdout",
    "wasi:cli/stderr",
    "wasi:cli/terminal-",
    "wasi:clocks/",
    "wasi:random/",
    "wasi:io/",
    "wasi:filesystem/",
];

fn features() -> WasmFeatures {
    let mut f = WasmFeatures::default();
    for off in [
        WasmFeatures::SIMD,
        WasmFeatures::RELAXED_SIMD,
        WasmFeatures::THREADS,
        WasmFeatures::SHARED_EVERYTHING_THREADS,
        WasmFeatures::GC,
        WasmFeatures::FUNCTION_REFERENCES,
        WasmFeatures::MEMORY64,
        WasmFeatures::MULTI_MEMORY,
        WasmFeatures::TAIL_CALL,
        WasmFeatures::EXCEPTIONS,
        WasmFeatures::LEGACY_EXCEPTIONS,
        WasmFeatures::STACK_SWITCHING,
        WasmFeatures::WIDE_ARITHMETIC,
    ] {
        f.remove(off);
    }
    f.insert(WasmFeatures::COMPONENT_MODEL);
    f
}

/// Validate a Sender component before anything compiles it.
pub fn validate_structure(bytes: &[u8], lim: &StructuralLimits) -> Result<(), String> {
    if bytes.len() > lim.max_bytes {
        return Err(format!(
            "component is {} bytes, above the {} byte limit",
            bytes.len(),
            lim.max_bytes
        ));
    }
    Validator::new_with_features(features())
        .validate_all(bytes)
        .map_err(|e| format!("invalid or disallowed wasm: {e}"))?;
    let (mut funcs, mut code, mut data, mut mems, mut tables, mut modules, mut imports) =
        (0u32, 0usize, 0usize, 0u32, 0u32, 0u32, 0u32);
    // The validator also accepts bare core modules: require a component.
    match Parser::new(0).parse_all(bytes).next() {
        Some(Ok(Payload::Version {
            encoding: wasmtime::wasmparser::Encoding::Component,
            ..
        })) => {}
        _ => return Err("not a WebAssembly component (core modules are not accepted)".into()),
    }
    for p in Parser::new(0).parse_all(bytes) {
        match p.map_err(|e| e.to_string())? {
            Payload::ModuleSection { .. } => modules += 1,
            Payload::FunctionSection(s) => funcs += s.count(),
            Payload::CodeSectionStart { size, .. } => code += size as usize,
            Payload::DataSection(s) => data += s.range().len(),
            Payload::MemorySection(s) => mems += s.count(),
            Payload::TableSection(s) => tables += s.count(),
            Payload::ComponentImportSection(s) => {
                for imp in s {
                    let imp = imp.map_err(|e| e.to_string())?;
                    imports += 1;
                    let name = imp.name.name;
                    if !ALLOWED_IMPORT_PREFIXES.iter().any(|p| name.starts_with(p)) {
                        return Err(format!(
                            "import `{name}` is not available to Sender components"
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    let checks = [
        (funcs as usize, lim.max_functions as usize, "functions"),
        (code, lim.max_code_bytes, "code bytes"),
        (data, lim.max_data_bytes, "data bytes"),
        (mems as usize, lim.max_memories as usize, "memories"),
        (tables as usize, lim.max_tables as usize, "tables"),
        (
            modules as usize,
            lim.max_core_modules as usize,
            "core modules",
        ),
        (imports as usize, lim.max_imports as usize, "imports"),
    ];
    for (n, max, what) in checks {
        if n > max {
            return Err(format!("{n} {what}, above the limit of {max}"));
        }
    }
    Ok(())
}

/// The restricted engine, configured identically in the compile worker and the
/// kernel workers (Wasmtime refuses artifacts from a different configuration).
pub fn restricted_engine(max_memory_bytes: u64) -> anyhow::Result<Engine> {
    let mut c = Config::new();
    c.wasm_component_model(true);
    c.consume_fuel(true);
    c.cranelift_nan_canonicalization(true);
    c.wasm_simd(false);
    c.wasm_relaxed_simd(false);
    c.wasm_gc(false);
    c.wasm_memory64(false);
    c.wasm_multi_memory(false);
    c.wasm_tail_call(false);
    c.wasm_wide_arithmetic(false);
    c.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
    c.cranelift_opt_level(wasmtime::OptLevel::Speed);
    // On-demand allocation: Sender components are rarer; memory is capped by the limiter.
    c.allocation_strategy(InstanceAllocationStrategy::OnDemand);
    c.memory_reservation(max_memory_bytes.next_power_of_two().max(1 << 26));
    Ok(Engine::new(&c)?)
}

pub(crate) struct Restricted {
    engine: Engine,
    compiled: parking_lot::Mutex<HashMap<String, Arc<sbindings::SenderKernelPre<crate::Ctx>>>>,
    limits: StructuralLimits,
}

impl Restricted {
    pub(crate) fn new(cfg: &EngineConfig) -> anyhow::Result<Self> {
        let engine = restricted_engine(cfg.max_memory_bytes)?;
        Ok(Restricted {
            engine,
            compiled: parking_lot::Mutex::new(HashMap::new()),
            limits: StructuralLimits::default(),
        })
    }
}

pub const COMPILE_TIMEOUT: Duration = Duration::from_secs(10);

impl KernelEngine {
    async fn compile_sender(
        &self,
        b64: &str,
    ) -> anyhow::Result<Arc<sbindings::SenderKernelPre<crate::Ctx>>> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| anyhow!("component is not base64"))?;
        let sha = remit_wire::sha256_hex(&bytes);
        if let Some(p) = self.restricted.compiled.lock().get(&sha) {
            return Ok(p.clone());
        }
        validate_structure(&bytes, &self.restricted.limits).map_err(|e| anyhow!(e))?;
        let engine = self.restricted.engine.clone();
        let task = tokio::task::spawn_blocking(move || Component::new(&engine, &bytes));
        let component = tokio::time::timeout(COMPILE_TIMEOUT, task)
            .await
            .map_err(|_| anyhow!("compile timeout"))?
            .map_err(|e| anyhow!("compile task: {e}"))?
            .map_err(|e| anyhow!("compile: {e}"))?;
        let linker = build_linker(&self.restricted.engine)?;
        let pre = Arc::new(sbindings::SenderKernelPre::new(
            linker.instantiate_pre(&component)?,
        )?);
        let mut c = self.restricted.compiled.lock();
        if c.len() > 256 {
            c.clear();
        }
        c.insert(sha, pre.clone());
        Ok(pre)
    }

    pub(crate) async fn run_component(
        &self,
        job: &KernelJob,
        host: Box<dyn ReadHost>,
    ) -> KernelOutcome {
        let t0 = Instant::now();
        let fail = |status: Status, log: String| KernelOutcome {
            status,
            result_cbor: vec![],
            fuel_used: 0,
            host_fuel: 0,
            wall_us: t0.elapsed().as_micros() as u64,
            instantiate_us: 0,
            log,
        };
        let compiled = match &job.compiled {
            // SAFETY: produced by the Holder's own compile worker (never by a
            // Sender; `KernelJob.compiled` is set only by `WorkerPool`), and
            // Wasmtime checks version and engine-config compatibility.
            Some(c) => unsafe { Component::deserialize(&self.restricted.engine, &c.0) }
                .map_err(anyhow::Error::from)
                .and_then(|c| Ok(build_linker(&self.restricted.engine)?.instantiate_pre(&c)?))
                .and_then(|p| Ok(Arc::new(sbindings::SenderKernelPre::new(p)?))),
            None => self.compile_sender(&job.source).await,
        };
        let pre = match compiled {
            Ok(p) => p,
            Err(e) => return fail(Status::Internal, format!("sender component rejected: {e}")),
        };
        let (mut store, stderr) = self.new_store_on(&self.restricted.engine);
        {
            let d = store.data_mut();
            d.host = host;
            d.clock
                .store(job.issued_at_ms, std::sync::atomic::Ordering::Relaxed);
            d.rng.reseed(&job.nonce, "secure");
            d.irng.reseed(&job.nonce, "insecure");
            d.limiter = Limiter::new(job.limits.memory_bytes as usize);
        }
        let _ = store.set_fuel(job.limits.fuel);
        let deadline = Duration::from_millis(job.limits.wall_ms.max(1));
        let mut instantiate_us = 0;
        let fut = async {
            let k = pre.instantiate_async(&mut store).await?;
            instantiate_us = t0.elapsed().as_micros() as u64;
            k.call_run(&mut store, &job.params_cbor).await
        };
        let res = tokio::time::timeout(deadline, fut).await;
        let remaining = store.get_fuel().unwrap_or(0);
        let ctx = store.data();
        let mut log = String::from_utf8_lossy(&stderr.contents()).to_string();
        let (status, result_cbor) = match res {
            Err(_) => (Status::LimitExceeded, vec![]),
            Ok(Ok(Ok(bytes))) => (Status::Ok, bytes),
            Ok(Ok(Err(code))) => (
                match code {
                    1 => Status::LimitExceeded,
                    2 => Status::TypeViolation,
                    3 => Status::Denied,
                    _ => Status::Internal,
                },
                vec![],
            ),
            Ok(Err(trap)) => {
                log.push_str(&format!(
                    "\ntrap: {}",
                    format!("{trap:?}").lines().next().unwrap_or("")
                ));
                (
                    if ctx.fuel_exhausted || remaining == 0 || ctx.limiter.hit {
                        Status::LimitExceeded
                    } else {
                        Status::Internal
                    },
                    vec![],
                )
            }
        };
        KernelOutcome {
            status,
            result_cbor,
            fuel_used: job.limits.fuel.saturating_sub(remaining),
            host_fuel: ctx.host_fuel,
            wall_us: t0.elapsed().as_micros() as u64,
            instantiate_us,
            log,
        }
    }
}
