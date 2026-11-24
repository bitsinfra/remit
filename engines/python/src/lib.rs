//! Remit Python kernel engine: Pydantic's Monty interpreter (a Rust-written
//! Python subset built for LLM code) compiled into the same `remit:kernel`
//! component world as the JS engine, for defense in depth (Monty inside
//! Wasm inside a worker process).
//!
//! Kernel contract (`lang: "python/monty"`):
//!
//! ```python
//! def main(reads, params):
//!     rows = reads["busy"]({"from": params["from"], "until": params["until"]})
//!     return len(rows)
//! ```
//!
//! Rows are dicts; timestamps are RFC 3339 strings. The result is
//! JSON-encoded inside the sandbox and validated by the Holder. Clock and PRNG
//! are fixed per remit (`issued_at`, nonce-derived seed).

use std::cell::RefCell;

use arrow_array::{cast::AsArray, types::*, Array, ArrayRef, RecordBatch};
use arrow_schema::{DataType, TimeUnit};
use monty::{MontyRun, RunProgress};
use monty_types::{CompileOptions, DateTimeSource, MontyObject, OsPolicy, PrintWriter, RandomSeed, RandomStart, ResourceLimits, ResourceTracker};
use serde_json::{json, Map, Value};

wit_bindgen::generate!({
    path: "../../spec/wit",
    world: "kernel",
});

use remit::kernel::{data, holder_fns};

const ST_LIMIT: u32 = 1;
const ST_DENIED: u32 = 3;
const ST_INTERNAL: u32 = 4;

struct State {
    source: String,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

const PRELUDE: &str = r#"
import json

def __remit_make(n):
    def read(p=None):
        return json.loads(__remit_read(n, json.dumps(p if p is not None else {})))
    return read

def holder(name, args=None):
    return json.loads(__remit_fn(name, json.dumps(args)))

reads = {}
for __n in json.loads(__remit_names):
    reads[__n] = __remit_make(__n)
params = json.loads(__remit_params)
"#;

const EPILOGUE: &str = "\njson.dumps(main(reads, params))\n";

fn program(source: &str) -> String {
    format!("{PRELUDE}\n{source}\n{EPILOGUE}")
}

fn inputs() -> Vec<String> {
    vec!["__remit_read".into(), "__remit_fn".into(), "__remit_names".into(), "__remit_params".into()]
}

struct Engine;

impl Guest for Engine {
    fn init() -> Result<(), String> {
        // Monty VMs start in microseconds; nothing to pre-initialize.
        Ok(())
    }

    fn load(source: String, _entry: String) -> Result<(), String> {
        // Compile once to surface syntax errors at load time.
        MontyRun::new(program(&source), "kernel.py", inputs(), CompileOptions::default()).map_err(|e| format!("SyntaxError: {e}"))?;
        if !source.contains("def main") {
            return Err("the kernel must define `def main(reads, params)`".into());
        }
        STATE.with(|s| *s.borrow_mut() = Some(State { source }));
        Ok(())
    }

    fn run(params: Vec<u8>) -> Result<Vec<u8>, u32> {
        let source = STATE.with(|s| s.borrow().as_ref().map(|st| st.source.clone())).ok_or(ST_INTERNAL)?;
        let p: ciborium::Value = ciborium::from_reader(params.as_slice()).map_err(|_| ST_INTERNAL)?;
        let pj = cbor_to_json(&p);
        // Determinism: fixed clock (issued_at via the frozen WASI clock) and seeded PRNG.
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let seed = {
            let mut b = [0u8; 8];
            getrandom_bytes(&mut b);
            i64::from_le_bytes(b)
        };
        let policy = OsPolicy {
            datetime: DateTimeSource::Fixed { unix_seconds: now_ms.div_euclid(1000), microsecond: (now_ms.rem_euclid(1000) * 1000) as u32 },
            random_start: RandomStart::Seed(RandomSeed::Int(seed.into())),
            ..Default::default()
        };
        let runner = MontyRun::new(program(&source), "kernel.py", inputs(), CompileOptions::default()).map_err(|_| ST_INTERNAL)?.with_os_policy(policy);
        let limits = ResourceLimits { max_suspensions: 10_000, ..ResourceLimits::default() };
        let names = serde_json::to_string(&data::declared()).map_err(|_| ST_INTERNAL)?;
        let mut progress = runner
            .start(
                vec![MontyObject::function("__remit_read", None), MontyObject::function("__remit_fn", None), MontyObject::string(names), MontyObject::string(pj.to_string())],
                ResourceTracker::new(limits),
                PrintWriter::Disabled,
            )
            .map_err(|e| {
                eprintln!("kernel error: {e}");
                ST_INTERNAL
            })?;
        loop {
            match progress {
                RunProgress::Complete(v) => {
                    let s = v.as_ref().as_str().ok_or(ST_INTERNAL)?.to_string();
                    let j: Value = serde_json::from_str(&s).map_err(|_| ST_INTERNAL)?;
                    let mut out = Vec::new();
                    ciborium::into_writer(&json_to_cbor(&j), &mut out).map_err(|_| ST_INTERNAL)?;
                    return Ok(out);
                }
                RunProgress::FunctionCall(call) if call.function_name == "__remit_read" => {
                    let name = call.args.arg(0).and_then(|a| a.as_str().map(String::from)).ok_or(ST_INTERNAL)?;
                    let args = call.args.arg(1).and_then(|a| a.as_str().map(String::from)).unwrap_or_else(|| "{}".into());
                    let rows = match read(&name, &args) {
                        Ok(r) => r,
                        Err(code) => return Err(code),
                    };
                    progress = call.resume(MontyObject::string(rows), PrintWriter::Disabled).map_err(|e| {
                        eprintln!("kernel error: {e}");
                        if e.to_string().contains("limit") { ST_LIMIT } else { ST_INTERNAL }
                    })?;
                }
                RunProgress::FunctionCall(call) if call.function_name == "__remit_fn" => {
                    let name = call.args.arg(0).and_then(|a| a.as_str().map(String::from)).ok_or(ST_INTERNAL)?;
                    let args = call.args.arg(1).and_then(|a| a.as_str().map(String::from)).unwrap_or_else(|| "null".into());
                    let v: Value = serde_json::from_str(&args).map_err(|_| ST_INTERNAL)?;
                    let mut buf = Vec::new();
                    ciborium::into_writer(&json_to_cbor(&v), &mut buf).map_err(|_| ST_INTERNAL)?;
                    let out = holder_fns::call(&name, &buf).map_err(|e| match e {
                        data::ErrorCode::RowCap | data::ErrorCode::CallCap => ST_LIMIT,
                        data::ErrorCode::Denied => ST_DENIED,
                        _ => ST_INTERNAL,
                    })?;
                    let out: ciborium::Value = ciborium::from_reader(out.as_slice()).map_err(|_| ST_INTERNAL)?;
                    progress = call.resume(MontyObject::string(cbor_to_json(&out).to_string()), PrintWriter::Disabled).map_err(|e| {
                        eprintln!("kernel error: {e}");
                        if e.to_string().contains("limit") { ST_LIMIT } else { ST_INTERNAL }
                    })?;
                }
                _ => {
                    eprintln!("kernel error: unsupported host interaction (os / import / name lookup)");
                    return Err(ST_DENIED);
                }
            }
        }
    }
}

fn getrandom_bytes(buf: &mut [u8]) {
    // std's wasip2 hashing seed path reads wasi:random, which the Holder seeds
    // from the remit nonce; use it through a HashMap-free route.
    use std::hash::{BuildHasher, Hasher};
    let s = std::collections::hash_map::RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(0x52454d4954);
    buf.copy_from_slice(&h.finish().to_le_bytes()[..buf.len()]);
}

fn read(name: &str, params_json: &str) -> Result<String, u32> {
    let r = data::bind(name).ok_or(ST_DENIED)?;
    let pj: Value = serde_json::from_str(params_json).map_err(|_| ST_INTERNAL)?;
    let mut buf = Vec::new();
    ciborium::into_writer(&json_to_cbor(&pj), &mut buf).map_err(|_| ST_INTERNAL)?;
    let t = r.call(&buf).map_err(|e| match e {
        data::ErrorCode::RowCap | data::ErrorCode::CallCap => ST_LIMIT,
        data::ErrorCode::Denied => ST_DENIED,
        _ => ST_INTERNAL,
    })?;
    let mut stream = t.schema();
    while let Some(b) = t.next_batch() {
        stream.extend_from_slice(&b);
    }
    let reader = arrow_ipc::reader::StreamReader::try_new(std::io::Cursor::new(stream), None).map_err(|_| ST_INTERNAL)?;
    let schema = reader.schema();
    let mut rows = Vec::new();
    for b in reader {
        let b: RecordBatch = b.map_err(|_| ST_INTERNAL)?;
        for i in 0..b.num_rows() {
            let mut m = Map::new();
            for (c, f) in schema.fields().iter().enumerate() {
                m.insert(f.name().clone(), cell(b.column(c), i));
            }
            rows.push(Value::Object(m));
        }
    }
    serde_json::to_string(&rows).map_err(|_| ST_INTERNAL)
}

fn cell(a: &ArrayRef, i: usize) -> Value {
    if a.is_null(i) {
        return Value::Null;
    }
    macro_rules! n {
        ($t:ty) => {
            json!(a.as_primitive::<$t>().value(i))
        };
    }
    match a.data_type() {
        DataType::Boolean => json!(a.as_boolean().value(i)),
        DataType::Int8 => n!(Int8Type),
        DataType::Int16 => n!(Int16Type),
        DataType::Int32 => n!(Int32Type),
        DataType::Int64 => n!(Int64Type),
        DataType::UInt32 => n!(UInt32Type),
        DataType::UInt64 => n!(UInt64Type),
        DataType::Float32 => n!(Float32Type),
        DataType::Float64 => n!(Float64Type),
        DataType::Utf8 => json!(a.as_string::<i32>().value(i)),
        DataType::LargeUtf8 => json!(a.as_string::<i64>().value(i)),
        DataType::Timestamp(u, _) => {
            let ms = match u {
                TimeUnit::Second => a.as_primitive::<TimestampSecondType>().value(i) * 1000,
                TimeUnit::Millisecond => a.as_primitive::<TimestampMillisecondType>().value(i),
                TimeUnit::Microsecond => a.as_primitive::<TimestampMicrosecondType>().value(i) / 1000,
                TimeUnit::Nanosecond => a.as_primitive::<TimestampNanosecondType>().value(i) / 1_000_000,
            };
            json!(iso(ms))
        }
        DataType::Date32 => json!(iso(a.as_primitive::<Date32Type>().value(i) as i64 * 86_400_000)[..10].to_string()),
        _ => Value::Null,
    }
}

fn iso(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60)
}

fn cbor_to_json(v: &ciborium::Value) -> Value {
    use ciborium::Value as C;
    match v {
        C::Null => Value::Null,
        C::Bool(b) => json!(b),
        C::Integer(i) => json!(i128::from(*i) as i64),
        C::Float(f) => json!(f),
        C::Text(s) => json!(s),
        C::Array(a) => Value::Array(a.iter().map(cbor_to_json).collect()),
        C::Map(m) => Value::Object(m.iter().filter_map(|(k, v)| k.as_text().map(|k| (k.to_string(), cbor_to_json(v)))).collect()),
        C::Tag(1, inner) => {
            let secs = match inner.as_ref() {
                C::Integer(i) => i128::from(*i) as f64,
                C::Float(f) => *f,
                _ => 0.0,
            };
            json!(iso((secs * 1000.0).round() as i64))
        }
        C::Tag(_, inner) => cbor_to_json(inner),
        _ => Value::Null,
    }
}

fn json_to_cbor(v: &Value) -> ciborium::Value {
    use ciborium::Value as C;
    match v {
        Value::Null => C::Null,
        Value::Bool(b) => C::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => C::Integer(i.into()),
            None => C::Float(n.as_f64().unwrap_or(0.0)),
        },
        Value::String(s) => C::Text(s.clone()),
        Value::Array(a) => C::Array(a.iter().map(json_to_cbor).collect()),
        Value::Object(o) => C::Map(o.iter().map(|(k, v)| (C::Text(k.clone()), json_to_cbor(v))).collect()),
    }
}

export!(Engine);
