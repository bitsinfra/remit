//! Remit compute plane: runs Sender kernels inside a Holder-built engine
//! component (the JS engine in `engines/js`) under Wasmtime.
//!
//! * **Only Holder-trusted bytes become machine code.** Senders ship source;
//!   the engine component is pinned by SHA-256 and compiled/cached by the
//!   Holder. Precompiled artifacts from outside are never accepted.
//! * **Zero ambient authority.** The `remit:kernel` world imports `data` and
//!   `holder-fns`. The engine's init-time WASI needs are satisfied with
//!   deterministic stubs (frozen clock at `issued_at`, nonce-seeded PRNG,
//!   empty env/args, no preopens). Sockets and HTTP are not linked at all.
//! * **Fuel-only metering.** The wall deadline is enforced at async fuel
//!   yields; host I/O is priced per call, row and byte via a call hook.
//! * **A trapped store is never reused**: every remit gets a fresh instance
//!   from the pooling allocator.

#[cfg(target_os = "linux")]
pub mod linux;
pub mod microvm;
pub mod sender;
pub mod shm;
pub mod snapshot;
pub mod worker;
pub use worker::WorkerPool;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasmtime::component::{Component, HasData, HasSelf, Linker, Resource, ResourceTable};
use wasmtime::{Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store};
use wasmtime_wasi::cli::WasiCliView;
use wasmtime_wasi::clocks::WasiClocksView;
use wasmtime_wasi::filesystem::WasiFilesystemView;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        // A copy of spec/wit, kept identical by `wit_matches_spec`.
        path: "wit",
        world: "kernel",
        imports: { default: async | trappable },
        exports: { default: async },
        with: {
            "remit:kernel/data.table": super::TableRes,
            "remit:kernel/data.read": super::ReadRes,
        },
    });
}

use bindings::remit::kernel::data::ErrorCode;

/// Fixed status set (spec/status.md). Codes are what the engine returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    LimitExceeded,
    TypeViolation,
    Denied,
    Internal,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::LimitExceeded => "limit_exceeded",
            Status::TypeViolation => "type_violation",
            Status::Denied => "denied",
            Status::Internal => "internal",
        }
    }
    fn from_code(c: u32) -> Self {
        match c {
            1 => Status::LimitExceeded,
            2 => Status::TypeViolation,
            3 => Status::Denied,
            _ => Status::Internal,
        }
    }
}

/// Errors a read can report to the kernel (mirrors the WIT `error-code`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadErr {
    RowCap,
    CallCap,
    ParamType,
    Denied,
    Internal,
}

impl From<ReadErr> for ErrorCode {
    fn from(e: ReadErr) -> Self {
        match e {
            ReadErr::RowCap => ErrorCode::RowCap,
            ReadErr::CallCap => ErrorCode::CallCap,
            ReadErr::ParamType => ErrorCode::ParamType,
            ReadErr::Denied => ErrorCode::Denied,
            ReadErr::Internal => ErrorCode::Internal,
        }
    }
}

/// A post-policy table handed to the kernel as Arrow IPC messages.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostTable {
    #[serde(with = "serde_bytes_b64")]
    pub schema_ipc: Vec<u8>,
    pub batches_ipc: Vec<ByteBuf>,
    pub rows: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ByteBuf(#[serde(with = "serde_bytes_b64")] pub Vec<u8>);

mod serde_bytes_b64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&STANDARD.encode(b))
        } else {
            s.serialize_bytes(b)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            return STANDARD.decode(s).map_err(serde::de::Error::custom);
        }
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E>(self, b: &[u8]) -> Result<Vec<u8>, E> {
                Ok(b.to_vec())
            }
            fn visit_byte_buf<E>(self, b: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(b)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// The Holder side of the `data` interface. Implemented by the Holder over
/// its read plane; the kernel never sees connectors or keys.
#[async_trait::async_trait]
pub trait ReadHost: Send {
    fn declared(&self) -> Vec<String>;
    /// Execute a declared read with JSON params (timestamps as RFC 3339).
    async fn call(
        &mut self,
        name: &str,
        params: serde_json::Map<String, Value>,
    ) -> Result<HostTable, ReadErr>;
    /// Holder functions (pure, priced). Default: none exist.
    async fn holder_fn(&mut self, _name: &str, _args: Value) -> Result<Value, ReadErr> {
        Err(ReadErr::Denied)
    }
    /// Prices of every callable Holder function (sent to workers).
    fn fn_prices(&self) -> BTreeMap<String, u64> {
        BTreeMap::new()
    }
    /// Fuel price of a Holder function (default: the flat list price).
    fn fn_price(&self, _name: &str) -> Option<u64> {
        None
    }
}

/// Fuel price list for host work (published in the catalog's runtime section).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FuelPrices {
    pub per_call: u64,
    pub per_row: u64,
    pub per_byte: u64,
    pub per_holder_fn: u64,
}

impl Default for FuelPrices {
    fn default() -> Self {
        FuelPrices {
            per_call: 50_000,
            per_row: 200,
            per_byte: 1,
            per_holder_fn: 100_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelLimits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub wall_ms: u64,
}

/// One kernel execution request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelJob {
    pub source: String,
    pub entry: String,
    /// CBOR-encoded params (timestamps as tag 1).
    #[serde(with = "serde_bytes_b64")]
    pub params_cbor: Vec<u8>,
    pub nonce: String,
    pub issued_at_ms: i64,
    pub limits: KernelLimits,
    /// `source` is a base64 Sender-built component (`lang = "wasm/component"`).
    #[serde(default)]
    pub component: bool,
    /// Artifact compiled by the Holder's own compile worker from a validated
    /// Sender component. Never accepted from outside the Holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled: Option<ByteBuf>,
}

/// Measured guest cost per unit of fuel (`remit bench --calibrate`):
/// (engine, target, ns per fuel). Reference hardware is named in
/// `bench/RESULTS.md`; host work is priced in the same unit ([`FuelPrices`]).
pub const FUEL_CALIBRATION: &[(&str, &str, f64)] = include!("calibration.in");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelOutcome {
    pub status: Status,
    /// CBOR result when `status == ok`.
    #[serde(with = "serde_bytes_b64")]
    pub result_cbor: Vec<u8>,
    /// Fuel charged to the Sender (guest instructions + priced host work).
    pub fuel_used: u64,
    pub host_fuel: u64,
    pub wall_us: u64,
    pub instantiate_us: u64,
    /// Holder-side diagnostics only (never returned to Senders).
    pub log: String,
}

// ---------------------------------------------------------------- host state

pub struct TableRes {
    schema: Vec<u8>,
    batches: std::collections::VecDeque<Vec<u8>>,
    rows: u64,
}

pub struct ReadRes {
    name: String,
}

pub(crate) struct Limiter {
    pub(crate) max_memory: usize,
    /// Bytes grown across *all* memories of the instance.
    pub(crate) grown: usize,
    pub(crate) hit: bool,
}

impl Limiter {
    pub(crate) fn new(max_memory: usize) -> Self {
        Limiter {
            max_memory,
            grown: 0,
            hit: false,
        }
    }
}

impl wasmtime::ResourceLimiter for Limiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.grown = self.grown.saturating_add(desired.saturating_sub(current));
        if desired > self.max_memory || self.grown > self.max_memory {
            self.hit = true;
            return Ok(false);
        }
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1_000_000)
    }
}

pub(crate) struct Ctx {
    table: ResourceTable,
    wasi: WasiCtx,
    host: Box<dyn ReadHost>,
    /// Rebindable per job (pre-initialized instances are created before the
    /// remit exists): frozen wall clock and PRNG stream.
    clock: Arc<std::sync::atomic::AtomicI64>,
    rng: SharedRng,
    irng: SharedRng,
    limiter: Limiter,
    prices: FuelPrices,
    pending_fuel: u64,
    host_fuel: u64,
    fuel_exhausted: bool,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl bindings::remit::kernel::data::Host for Ctx {
    async fn declared(&mut self) -> wasmtime::Result<Vec<String>> {
        Ok(self.host.declared())
    }
    async fn bind(&mut self, name: String) -> wasmtime::Result<Option<Resource<ReadRes>>> {
        if !self.host.declared().contains(&name) {
            return Ok(None);
        }
        Ok(Some(self.table.push(ReadRes { name })?))
    }
}

impl bindings::remit::kernel::data::HostRead for Ctx {
    async fn call(
        &mut self,
        r: Resource<ReadRes>,
        params: Vec<u8>,
    ) -> wasmtime::Result<Result<Resource<TableRes>, ErrorCode>> {
        let name = self.table.get(&r)?.name.clone();
        let p: ciborium::Value = match ciborium::from_reader(params.as_slice()) {
            Ok(v) => v,
            Err(_) => return Ok(Err(ErrorCode::ParamType)),
        };
        let pj = match cbor_to_json(&p) {
            Value::Object(m) => m,
            Value::Null => serde_json::Map::new(),
            _ => return Ok(Err(ErrorCode::ParamType)),
        };
        self.pending_fuel += self.prices.per_call;
        match self.host.call(&name, pj).await {
            Ok(t) => {
                self.pending_fuel += t.rows * self.prices.per_row + t.bytes * self.prices.per_byte;
                let res = TableRes {
                    schema: t.schema_ipc,
                    batches: t.batches_ipc.into_iter().map(|b| b.0).collect(),
                    rows: t.rows,
                };
                Ok(Ok(self.table.push(res)?))
            }
            Err(e) => Ok(Err(e.into())),
        }
    }
    async fn drop(&mut self, r: Resource<ReadRes>) -> wasmtime::Result<()> {
        self.table.delete(r)?;
        Ok(())
    }
}

impl bindings::remit::kernel::data::HostTable for Ctx {
    async fn schema(&mut self, t: Resource<TableRes>) -> wasmtime::Result<Vec<u8>> {
        Ok(self.table.get(&t)?.schema.clone())
    }
    async fn next_batch(&mut self, t: Resource<TableRes>) -> wasmtime::Result<Option<Vec<u8>>> {
        Ok(self.table.get_mut(&t)?.batches.pop_front())
    }
    async fn num_rows(&mut self, t: Resource<TableRes>) -> wasmtime::Result<u64> {
        Ok(self.table.get(&t)?.rows)
    }
    async fn drop(&mut self, t: Resource<TableRes>) -> wasmtime::Result<()> {
        self.table.delete(t)?;
        Ok(())
    }
}

impl bindings::remit::kernel::holder_fns::Host for Ctx {
    async fn call(
        &mut self,
        name: String,
        args: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, ErrorCode>> {
        let a: ciborium::Value = match ciborium::from_reader(args.as_slice()) {
            Ok(v) => v,
            Err(_) => return Ok(Err(ErrorCode::ParamType)),
        };
        self.pending_fuel += self
            .host
            .fn_price(&name)
            .unwrap_or(self.prices.per_holder_fn);
        match self.host.holder_fn(&name, cbor_to_json(&a)).await {
            Ok(v) => {
                let mut out = Vec::new();
                ciborium::into_writer(&json_to_cbor(&v), &mut out)?;
                self.pending_fuel += out.len() as u64 * self.prices.per_byte;
                Ok(Ok(out))
            }
            Err(e) => Ok(Err(e.into())),
        }
    }
}

/// CBOR → JSON (tag 1 epoch seconds → RFC 3339).
pub fn cbor_to_json(v: &ciborium::Value) -> Value {
    use ciborium::Value as C;
    match v {
        C::Null => Value::Null,
        C::Bool(b) => Value::Bool(*b),
        C::Integer(i) => {
            let n = i128::from(*i);
            if let Ok(x) = i64::try_from(n) {
                Value::from(x)
            } else {
                Value::from(n as f64)
            }
        }
        C::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        C::Text(s) => Value::String(s.clone()),
        C::Bytes(b) => Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b,
        )),
        C::Array(a) => Value::Array(a.iter().map(cbor_to_json).collect()),
        C::Map(m) => {
            let mut o = serde_json::Map::new();
            for (k, val) in m {
                if let C::Text(k) = k {
                    o.insert(k.clone(), cbor_to_json(val));
                }
            }
            Value::Object(o)
        }
        C::Tag(1, inner) => {
            let secs = match inner.as_ref() {
                C::Integer(i) => i128::from(*i) as f64,
                C::Float(f) => *f,
                _ => f64::NAN,
            };
            if secs.is_finite() {
                Value::String(format_ts((secs * 1000.0).round() as i64))
            } else {
                Value::Null
            }
        }
        C::Tag(_, inner) => cbor_to_json(inner),
        _ => Value::Null,
    }
}

/// JSON → CBOR. With `timestamps`, string values for those keys become tag 1.
pub fn json_to_cbor(v: &Value) -> ciborium::Value {
    use ciborium::Value as C;
    match v {
        Value::Null => C::Null,
        Value::Bool(b) => C::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                C::Integer(i.into())
            } else {
                C::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => C::Text(s.clone()),
        Value::Array(a) => C::Array(a.iter().map(json_to_cbor).collect()),
        Value::Object(o) => C::Map(
            o.iter()
                .map(|(k, v)| (C::Text(k.clone()), json_to_cbor(v)))
                .collect(),
        ),
    }
}

/// Encode kernel params: params whose names are timestamp-typed become Dates.
pub fn encode_params(
    params: &serde_json::Map<String, Value>,
    timestamp_keys: &[String],
) -> Vec<u8> {
    use ciborium::Value as C;
    let m = params
        .iter()
        .map(|(k, v)| {
            let cv = match v {
                Value::String(s) if timestamp_keys.contains(k) => match parse_ts(s) {
                    Some(ms) => C::Tag(1, Box::new(C::Float(ms as f64 / 1000.0))),
                    None => C::Text(s.clone()),
                },
                v => json_to_cbor(v),
            };
            (C::Text(k.clone()), cv)
        })
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&C::Map(m), &mut out).expect("cbor");
    out
}

fn parse_ts(s: &str) -> Option<i64> {
    // RFC 3339 only (params are canonicalized by the Holder before this point).
    let dt = time_parse(s)?;
    Some(dt)
}

fn time_parse(s: &str) -> Option<i64> {
    // Minimal RFC 3339 parser: YYYY-MM-DDTHH:MM:SS(.sss)?(Z|±HH:MM)
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut i = 19;
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        let f: String = frac.chars().chain(std::iter::repeat('0')).take(3).collect();
        ms = f.parse().ok()?;
    }
    let off = match b.get(i)? {
        b'Z' | b'z' => 0,
        b'+' | b'-' => {
            let sign = if b[i] == b'+' { 1 } else { -1 };
            sign * (num(i + 1..i + 3)? * 60 + num(i + 4..i + 6)?) * 60_000
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    Some(((days * 24 + h) * 60 + mi) * 60_000 + se * 1000 + ms - off)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn format_ts(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (h, mi, s, milli) = (
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000,
    );
    if milli == 0 {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
    }
}

// ------------------------------------------------------- deterministic stubs

/// Wall clock frozen at the remit's `issued_at` (set when the job binds).
struct FrozenWall(Arc<std::sync::atomic::AtomicI64>);
impl wasmtime_wasi::HostWallClock for FrozenWall {
    fn resolution(&self) -> Duration {
        Duration::from_millis(1)
    }
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(std::sync::atomic::Ordering::Relaxed).max(0) as u64)
    }
}

/// ChaCha20 stream seeded from the remit nonce, reseeded when a job binds to
/// a pre-initialized instance (initialization uses a fixed placeholder seed,
/// so every pooled instance starts identical).
#[derive(Clone)]
struct SharedRng(Arc<parking_lot::Mutex<rand_chacha::ChaCha20Rng>>);

impl SharedRng {
    fn new(nonce: &str, domain: &str) -> Self {
        SharedRng(Arc::new(parking_lot::Mutex::new(
            rand_chacha::ChaCha20Rng::from_seed(seed32(nonce, domain)),
        )))
    }
    fn reseed(&self, nonce: &str, domain: &str) {
        *self.0.lock() = rand_chacha::ChaCha20Rng::from_seed(seed32(nonce, domain));
    }
}

impl rand10::TryRng for SharedRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.lock().next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.lock().next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.lock().fill_bytes(dst);
        Ok(())
    }
}

fn seed32(nonce: &str, domain: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(format!("remit:{domain}:{nonce}").as_bytes()).into()
}

struct FrozenMono;
impl wasmtime_wasi::HostMonotonicClock for FrozenMono {
    fn resolution(&self) -> u64 {
        1_000_000
    }
    fn now(&self) -> u64 {
        0
    }
}

struct HasIo;
impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// Link exactly what the engine needs: `remit:kernel` imports plus
/// deterministic WASI stubs. No sockets, no HTTP.
pub(crate) fn build_linker(engine: &Engine) -> anyhow::Result<Linker<Ctx>> {
    use wasmtime_wasi::p2::bindings::{cli, clocks, filesystem, random};
    let mut l: Linker<Ctx> = Linker::new(engine);
    bindings::Kernel::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut l, |c| c)?;
    wasmtime_wasi_io_bindings(&mut l)?;
    clocks::wall_clock::add_to_linker::<Ctx, wasmtime_wasi::clocks::WasiClocks>(&mut l, |t| {
        t.clocks()
    })?;
    clocks::monotonic_clock::add_to_linker::<Ctx, wasmtime_wasi::clocks::WasiClocks>(
        &mut l,
        |t| t.clocks(),
    )?;
    random::random::add_to_linker::<Ctx, wasmtime_wasi::random::WasiRandom>(&mut l, |t| {
        t.wasi.random()
    })?;
    random::insecure::add_to_linker::<Ctx, wasmtime_wasi::random::WasiRandom>(&mut l, |t| {
        t.wasi.random()
    })?;
    random::insecure_seed::add_to_linker::<Ctx, wasmtime_wasi::random::WasiRandom>(&mut l, |t| {
        t.wasi.random()
    })?;
    cli::exit::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::environment::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::stdin::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::stdout::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::stderr::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::terminal_input::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::terminal_output::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::terminal_stdin::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::terminal_stdout::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    cli::terminal_stderr::add_to_linker::<Ctx, wasmtime_wasi::cli::WasiCli>(&mut l, |t| t.cli())?;
    // Rust std's wasip2 runtime imports filesystem preopens/types; with no
    // preopens configured, there is nothing to open.
    filesystem::preopens::add_to_linker::<Ctx, wasmtime_wasi::filesystem::WasiFilesystem>(
        &mut l,
        |t| t.filesystem(),
    )?;
    filesystem::types::add_to_linker::<Ctx, wasmtime_wasi::filesystem::WasiFilesystem>(
        &mut l,
        |t| t.filesystem(),
    )?;
    Ok(l)
}

fn wasmtime_wasi_io_bindings(l: &mut Linker<Ctx>) -> anyhow::Result<()> {
    wasmtime_wasi::p2::bindings::io::error::add_to_linker::<Ctx, HasIo>(l, |t| &mut t.table)?;
    wasmtime_wasi::p2::bindings::io::poll::add_to_linker::<Ctx, HasIo>(l, |t| &mut t.table)?;
    wasmtime_wasi::p2::bindings::io::streams::add_to_linker::<Ctx, HasIo>(l, |t| &mut t.table)?;
    Ok(())
}

// -------------------------------------------------------------------- engine

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    /// Path to the engine component (`remit_engine_js.wasm`).
    pub component: PathBuf,
    /// Expected SHA-256 of the component (hex). Startup fails on mismatch.
    pub sha256: Option<String>,
    /// Directory for compiled-artifact cache (Holder-built bytes only).
    pub cache_dir: Option<PathBuf>,
    pub pool_instances: u32,
    pub max_memory_bytes: u64,
    /// Fuel consumed between async yields (wall-deadline check cadence).
    pub yield_interval: u64,
    pub prices: FuelPrices,
    /// Pre-initialized instances kept ready (0 disables the pool).
    pub warm_instances: usize,
    /// Kernel language the component implements (`js/es2023`, `python/monty`).
    pub lang: String,
    /// Pre-initialize the engine once with Wizer and start every instance
    /// from that copy-on-write image (default on; falls back to running
    /// `init()` per instance if snapshotting fails).
    pub snapshot: bool,
    /// Compile for the architecture's baseline CPU instead of this machine's
    /// features, so the artifact also loads inside a VM that hides some.
    pub baseline_cpu: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            component: PathBuf::from("engines/js/dist/remit_engine_js.wasm"),
            sha256: None,
            cache_dir: None,
            pool_instances: 64,
            max_memory_bytes: 256 << 20,
            yield_interval: 2_000_000,
            prices: FuelPrices::default(),
            warm_instances: 8,
            lang: "js/es2023".into(),
            snapshot: true,
            baseline_cpu: false,
        }
    }
}

pub struct KernelEngine {
    engine: Engine,
    pre: bindings::KernelPre<Ctx>,
    cfg: EngineConfig,
    engine_sha256: String,
    /// Instances start from a Wizer image taken after `init()`.
    snapshotted: bool,
    /// Measured fuel to load an empty program into a pre-initialized engine.
    baseline_load_fuel: u64,
    /// Pre-initialized instances (engine realm + prelude), each used exactly
    /// once: the pooled equivalent of a snapshotted engine image.
    warm: parking_lot::Mutex<Vec<Warm>>,
    refilling: std::sync::atomic::AtomicBool,
    /// Restricted engine + compiled Sender components (by sha256).
    pub(crate) restricted: sender::Restricted,
}

struct Warm {
    store: Store<Ctx>,
    kernel: bindings::Kernel,
    stderr: wasmtime_wasi::p2::pipe::MemoryOutputPipe,
}

struct NoReads;
#[async_trait::async_trait]
impl ReadHost for NoReads {
    fn declared(&self) -> Vec<String> {
        vec![]
    }
    async fn call(
        &mut self,
        _: &str,
        _: serde_json::Map<String, Value>,
    ) -> Result<HostTable, ReadErr> {
        Err(ReadErr::Denied)
    }
}

const INIT_FUEL: u64 = u64::MAX / 4;

impl std::fmt::Debug for KernelEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelEngine")
            .field("engine_sha256", &self.engine_sha256)
            .finish()
    }
}

pub fn wasmtime_version() -> &'static str {
    "48.0.10"
}

fn wasmtime_config(cfg: &EngineConfig) -> anyhow::Result<Config> {
    let mut c = Config::new();
    c.wasm_component_model(true);
    c.consume_fuel(true);
    c.epoch_interruption(false);
    // Determinism / minimal feature set.
    c.cranelift_nan_canonicalization(true);
    c.wasm_relaxed_simd(false);
    c.wasm_memory64(false);
    c.wasm_gc(false);
    c.wasm_wide_arithmetic(false);
    c.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
    c.cranelift_opt_level(wasmtime::OptLevel::Speed);
    if cfg.baseline_cpu {
        c.target(&format!("{}-unknown-linux-gnu", std::env::consts::ARCH))?;
    }
    let mut pool = PoolingAllocationConfig::default();
    pool.total_component_instances(cfg.pool_instances);
    pool.total_core_instances(cfg.pool_instances * 4);
    pool.total_memories(cfg.pool_instances * 4);
    pool.total_tables(cfg.pool_instances * 8);
    pool.max_memory_size(cfg.max_memory_bytes as usize);
    pool.max_memories_per_component(4);
    pool.max_core_instances_per_component(64);
    pool.max_tables_per_component(16);
    pool.table_elements(100_000);
    pool.linear_memory_keep_resident(1 << 20);
    pool.table_keep_resident(1 << 16);
    c.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    c.memory_reservation(cfg.max_memory_bytes.next_power_of_two().max(1 << 26));
    c.memory_guard_size(1 << 16);
    Ok(c)
}

impl KernelEngine {
    /// Load, verify (by hash), compile (or load from the Holder's own cache)
    /// and pre-link the engine component, measure the baseline load cost and
    /// fill the pool of pre-initialized instances.
    pub async fn new(cfg: EngineConfig) -> anyhow::Result<Arc<Self>> {
        let bytes = std::fs::read(&cfg.component)
            .with_context(|| format!("engine component {}", cfg.component.display()))?;
        let sha = remit_wire::sha256_hex(&bytes);
        if let Some(expected) = &cfg.sha256 {
            if !remit_wire::manifest::eq_hash(expected, &sha) {
                return Err(anyhow!(
                    "engine component hash mismatch: expected {expected}, got {sha}"
                ));
            }
        }
        let wcfg = wasmtime_config(&cfg)?;
        let engine = Engine::new(&wcfg)?;
        let (image, snapshotted) = if cfg.snapshot {
            match engine_image(&cfg, &bytes, &sha).await {
                Ok(img) => (img, true),
                Err(e) => {
                    tracing::warn!("engine snapshot failed, running init() per instance: {e:#}");
                    (bytes.clone(), false)
                }
            }
        } else {
            (bytes.clone(), false)
        };
        let image_sha = remit_wire::sha256_hex(&image);
        let component = load_component(&engine, &image, &image_sha, cfg.cache_dir.as_deref())?;
        let linker = build_linker(&engine)?;
        let instance_pre = linker.instantiate_pre(&component)?;
        let pre = bindings::KernelPre::new(instance_pre)?;
        let cfg_clone = cfg.clone();
        let mut me = KernelEngine {
            engine,
            pre,
            cfg,
            engine_sha256: sha,
            snapshotted,
            baseline_load_fuel: 0,
            warm: parking_lot::Mutex::new(Vec::new()),
            refilling: std::sync::atomic::AtomicBool::new(false),
            restricted: sender::Restricted::new(&cfg_clone)?,
        };
        me.baseline_load_fuel = me.measure_baseline().await?;
        let me = Arc::new(me);
        me.refill().await;
        Ok(me)
    }

    pub fn engine_sha256(&self) -> &str {
        &self.engine_sha256
    }

    pub fn baseline_load_fuel(&self) -> u64 {
        self.baseline_load_fuel
    }

    pub fn prices(&self) -> FuelPrices {
        self.cfg.prices
    }

    /// Number of ready pre-initialized instances.
    pub fn warm_instances(&self) -> usize {
        self.warm.lock().len()
    }

    async fn measure_baseline(&self) -> anyhow::Result<u64> {
        let mut w = self.make_warm().await?;
        w.store.set_fuel(INIT_FUEL)?;
        w.kernel
            .call_load(
                &mut w.store,
                if self.cfg.lang.starts_with("python") {
                    "def main(reads, params):\n    return None\n"
                } else {
                    "export default function main() { return null; }"
                },
                "main",
            )
            .await?
            .map_err(|e| anyhow!("baseline load failed: {e}"))?;
        Ok(INIT_FUEL - w.store.get_fuel()?)
    }

    /// Instantiate and initialize the engine (Holder-paid, before any Sender
    /// input exists). Clock, PRNG, limits and reads are bound per job.
    async fn make_warm(&self) -> anyhow::Result<Warm> {
        let (mut store, stderr) = self.new_store();
        store.set_fuel(INIT_FUEL)?;
        let kernel = self.pre.instantiate_async(&mut store).await?;
        if !self.snapshotted {
            kernel
                .call_init(&mut store)
                .await?
                .map_err(|e| anyhow!("engine init failed: {e}"))?;
        }
        Ok(Warm {
            store,
            kernel,
            stderr,
        })
    }

    async fn refill(self: &Arc<Self>) {
        use std::sync::atomic::Ordering;
        if self.cfg.warm_instances == 0 || self.refilling.swap(true, Ordering::AcqRel) {
            return;
        }
        while self.warm.lock().len() < self.cfg.warm_instances {
            match self.make_warm().await {
                Ok(w) => self.warm.lock().push(w),
                Err(e) => {
                    tracing::warn!("kernel pool refill failed: {e}");
                    break;
                }
            }
        }
        self.refilling.store(false, Ordering::Release);
    }

    pub(crate) fn new_store(&self) -> (Store<Ctx>, wasmtime_wasi::p2::pipe::MemoryOutputPipe) {
        self.new_store_on(&self.engine)
    }

    pub(crate) fn new_store_on(
        &self,
        engine: &Engine,
    ) -> (Store<Ctx>, wasmtime_wasi::p2::pipe::MemoryOutputPipe) {
        new_store_with(&self.cfg, engine)
    }

    /// Whether instances start from a pre-initialized (Wizer) image.
    pub fn snapshotted(&self) -> bool {
        self.snapshotted
    }
}

pub(crate) fn new_store_with(
    cfg: &EngineConfig,
    engine: &Engine,
) -> (Store<Ctx>, wasmtime_wasi::p2::pipe::MemoryOutputPipe) {
    {
        let stderr = wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(16 * 1024);
        let clock = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let rng = SharedRng::new("init", "secure");
        let irng = SharedRng::new("init", "insecure");
        let mut b = wasmtime_wasi::WasiCtxBuilder::new();
        b.wall_clock(FrozenWall(clock.clone()))
            .monotonic_clock(FrozenMono)
            .secure_random(rng.clone())
            .insecure_random(irng.clone())
            .insecure_random_seed(u128::from_le_bytes(
                seed32("init", "seed")[..16].try_into().unwrap(),
            ))
            .stderr(stderr.clone())
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false);
        let ctx = Ctx {
            table: ResourceTable::new(),
            wasi: b.build(),
            host: Box::new(NoReads),
            clock,
            rng,
            irng,
            limiter: Limiter::new(cfg.max_memory_bytes as usize),
            prices: cfg.prices,
            pending_fuel: 0,
            host_fuel: 0,
            fuel_exhausted: false,
        };
        let mut store = Store::new(engine, ctx);
        store.limiter(|c| &mut c.limiter);
        store
            .fuel_async_yield_interval(Some(cfg.yield_interval))
            .expect("fuel yield");
        // Price host work: deduct pending fuel when control returns to the guest.
        store.call_hook(|mut ctx, hook| {
            if matches!(hook, wasmtime::CallHook::ReturningFromHost) {
                let pending = std::mem::take(&mut ctx.data_mut().pending_fuel);
                if pending > 0 {
                    ctx.data_mut().host_fuel += pending;
                    let f = ctx.get_fuel()?;
                    if f < pending {
                        ctx.data_mut().fuel_exhausted = true;
                        ctx.set_fuel(0)?;
                        return Err(wasmtime::format_err!("remit: fuel exhausted by host work"));
                    }
                    ctx.set_fuel(f - pending)?;
                }
            }
            Ok(())
        });
        (store, stderr)
    }
}

/// The engine image to compile: a Wizer snapshot of the pinned engine, cached
/// in the Holder's data dir by H(engine) ‖ Wasmtime version (Holder-made
/// bytes only, like the `.cwasm` cache).
async fn engine_image(cfg: &EngineConfig, bytes: &[u8], sha: &str) -> anyhow::Result<Vec<u8>> {
    let path = cfg.cache_dir.as_ref().map(|d| {
        d.join(format!(
            "{sha}-wasmtime{}.snapshot.wasm",
            wasmtime_version()
        ))
    });
    if let Some(p) = &path {
        if let Ok(b) = std::fs::read(p) {
            return Ok(b);
        }
    }
    let img = snapshot::preinitialize(cfg, bytes).await?;
    if let Some(p) = &path {
        let _ = std::fs::create_dir_all(p.parent().unwrap());
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, &img).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
    Ok(img)
}

impl KernelEngine {
    /// Run one kernel in this process (isolation level `inprocess`, or inside
    /// a `process` worker). Takes a pre-initialized instance from the pool
    /// (falling back to a fresh one) and never returns it.
    pub async fn run(self: &Arc<Self>, job: &KernelJob, host: Box<dyn ReadHost>) -> KernelOutcome {
        if job.component {
            return self.run_component(job, host).await;
        }
        let t0 = Instant::now();
        let pooled = self.warm.lock().pop();
        let mut w = match pooled {
            Some(w) => w,
            None => match self.make_warm().await {
                Ok(w) => w,
                Err(e) => {
                    return KernelOutcome {
                        status: Status::Internal,
                        result_cbor: vec![],
                        fuel_used: 0,
                        host_fuel: 0,
                        wall_us: 0,
                        instantiate_us: 0,
                        log: format!("instantiate: {e}"),
                    }
                }
            },
        };
        if self.cfg.warm_instances > 0 {
            let me = self.clone();
            tokio::spawn(async move { me.refill().await });
        }
        let instantiate_us = t0.elapsed().as_micros() as u64;
        // Bind the job.
        {
            let d = w.store.data_mut();
            d.host = host;
            d.clock
                .store(job.issued_at_ms, std::sync::atomic::Ordering::Relaxed);
            d.rng.reseed(&job.nonce, "secure");
            d.irng.reseed(&job.nonce, "insecure");
            d.limiter = Limiter::new(job.limits.memory_bytes as usize);
            d.pending_fuel = 0;
            d.host_fuel = 0;
            d.fuel_exhausted = false;
        }
        let budget = self.baseline_load_fuel + job.limits.fuel;
        let deadline = Duration::from_millis(job.limits.wall_ms.max(1));
        let _ = w.store.set_fuel(budget);
        let Warm {
            mut store,
            kernel: k,
            stderr,
        } = w;
        let fut = async {
            match k.call_load(&mut store, &job.source, &job.entry).await? {
                Ok(()) => {}
                Err(msg) => return Ok::<_, anyhow::Error>(Err((Status::Internal, msg))),
            }
            match k.call_run(&mut store, &job.params_cbor).await? {
                Ok(bytes) => Ok(Ok(bytes)),
                Err(code) => Ok(Err((
                    Status::from_code(code),
                    format!("kernel returned status {code}"),
                ))),
            }
        };
        let res = tokio::time::timeout(deadline, fut).await;
        let remaining = store.get_fuel().unwrap_or(0);
        let fuel_used = budget
            .saturating_sub(remaining)
            .saturating_sub(self.baseline_load_fuel);
        let ctx = store.data();
        let mut log = String::from_utf8_lossy(&stderr.contents()).to_string();
        let (status, result_cbor) = match res {
            Err(_) => {
                log.push_str("\nwall-time limit exceeded");
                (Status::LimitExceeded, vec![])
            }
            Ok(Ok(Ok(bytes))) => (Status::Ok, bytes),
            Ok(Ok(Err((st, msg)))) => {
                log.push_str(&format!("\n{msg}"));
                (st, vec![])
            }
            Ok(Err(trap)) => {
                let s = format!("{trap:?}");
                let st = if ctx.fuel_exhausted
                    || s.contains("all fuel consumed")
                    || s.contains("fuel exhausted")
                    || remaining == 0
                    || ctx.limiter.hit
                {
                    Status::LimitExceeded
                } else {
                    Status::Internal
                };
                log.push_str(&format!("\ntrap: {}", s.lines().next().unwrap_or("")));
                (st, vec![])
            }
        };
        KernelOutcome {
            status,
            result_cbor,
            fuel_used: fuel_used.min(job.limits.fuel.max(fuel_used)),
            host_fuel: ctx.host_fuel,
            wall_us: t0.elapsed().as_micros() as u64,
            instantiate_us,
            log,
        }
    }
}

fn load_component(
    engine: &Engine,
    bytes: &[u8],
    sha: &str,
    cache: Option<&Path>,
) -> anyhow::Result<Component> {
    // Cache key: H(wasm) ‖ wasmtime version ‖ engine config ‖ target.
    let key = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(sha.as_bytes());
        h.update(wasmtime_version().as_bytes());
        {
            use std::hash::{Hash, Hasher};
            let mut dh = std::collections::hash_map::DefaultHasher::new();
            engine.precompile_compatibility_hash().hash(&mut dh);
            h.update(dh.finish().to_le_bytes());
        }
        h.update(std::env::consts::ARCH.as_bytes());
        hex::encode(h.finalize())
    };
    if let Some(dir) = cache {
        let p = dir.join(format!("{key}.cwasm"));
        if p.exists() {
            // SAFETY: the file is produced below by this Holder from bytes it
            // verified by hash; it is never accepted from outside.
            if let Ok(c) = unsafe { Component::deserialize_file(engine, &p) } {
                return Ok(c);
            }
        }
        let c = Component::new(engine, bytes)?;
        let _ = std::fs::create_dir_all(dir);
        if let Ok(ser) = c.serialize() {
            let tmp = dir.join(format!("{key}.tmp"));
            if std::fs::write(&tmp, ser).is_ok() {
                let _ = std::fs::rename(&tmp, &p);
            }
        }
        return Ok(c);
    }
    Ok(Component::new(engine, bytes)?)
}

/// Minimal in-memory `ReadHost` used by tests and `remit dev` dry-runs.
pub struct StaticReads {
    pub tables: BTreeMap<String, HostTable>,
    pub max_calls: BTreeMap<String, u32>,
    pub calls: BTreeMap<String, u32>,
}

#[async_trait::async_trait]
impl ReadHost for StaticReads {
    fn declared(&self) -> Vec<String> {
        self.tables.keys().cloned().collect()
    }
    async fn call(
        &mut self,
        name: &str,
        _params: serde_json::Map<String, Value>,
    ) -> Result<HostTable, ReadErr> {
        let n = self.calls.entry(name.to_string()).or_default();
        *n += 1;
        if *n > *self.max_calls.get(name).unwrap_or(&1) {
            return Err(ReadErr::CallCap);
        }
        self.tables.get(name).cloned().ok_or(ReadErr::Denied)
    }
}

#[cfg(test)]
mod tests;
