//! Remit JS kernel engine: a Holder-built component that interprets Sender
//! source with the Boa engine inside Wasm. Only Holder-trusted bytes (this
//! component) become machine code; Sender code is interpreted.
//!
//! Determinism: the component's only clock/entropy come from the host's
//! deterministic WASI stubs (frozen at `issued_at`, PRNG seeded from nonce).

use std::cell::RefCell;
use std::collections::BTreeMap;

use arrow_array::{
    cast::AsArray, types::*, Array, ArrayRef, RecordBatch,
};
use arrow_schema::{DataType, TimeUnit};
use boa_engine::{
    js_string,
    native_function::NativeFunction,
    object::builtins::JsArray,
    property::PropertyKey,
    Context, JsError, JsNativeError, JsObject, JsResult, JsString, JsValue, Module, Source,
};
use ciborium::Value as Cbor;

wit_bindgen::generate!({
    path: "../../spec/wit",
    world: "kernel",
});

use remit::kernel::{data, holder_fns};

struct State {
    ctx: Context,
    main: Option<JsObject>,
    reads: Option<JsObject>,
}

fn do_init() -> Result<(), String> {
    let mut ctx = Context::default();
    install_natives(&mut ctx).map_err(|e| e.to_string())?;
    ctx.eval(Source::from_bytes(PRELUDE)).map_err(|e| format!("prelude: {e}"))?;
    STATE.with(|s| *s.borrow_mut() = Some(State { ctx, main: None, reads: None }));
    Ok(())
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    /// Decoded tables; columns are converted to JS only when accessed.
    static TABLES: RefCell<Vec<(Vec<RecordBatch>, usize)>> = const { RefCell::new(Vec::new()) };
    static BOUND: RefCell<BTreeMap<String, data::Read>> = const { RefCell::new(BTreeMap::new()) };
}

const PRELUDE: &str = include_str!("prelude.js");

// Status codes (spec/status.md): 1 limit_exceeded, 2 type_violation, 3 denied, 4 internal.
const ST_LIMIT: u32 = 1;
const ST_DENIED: u32 = 3;
const ST_INTERNAL: u32 = 4;

struct Engine;

impl Guest for Engine {
    fn init() -> Result<(), String> {
        if STATE.with(|s| s.borrow().is_some()) {
            return Ok(());
        }
        do_init()
    }

    fn load(source: String, entry: String) -> Result<(), String> {
        if STATE.with(|s| s.borrow().is_none()) {
            do_init()?;
        }
        let mut st = STATE.with(|s| s.borrow_mut().take()).ok_or("engine not initialized")?;
        let r = load_into(&mut st, &source, &entry);
        STATE.with(|s| *s.borrow_mut() = Some(st));
        r
    }

    fn run(params: Vec<u8>) -> Result<Vec<u8>, u32> {
        run_impl(params)
    }
}

fn load_into(st: &mut State, source: &str, entry: &str) -> Result<(), String> {
        let ctx = &mut st.ctx;
        let mk = ctx.global_object().get(js_string!("__remit_make_reads"), ctx).map_err(|e| e.to_string())?;
        let reads = mk
            .as_callable()
            .ok_or("reads already bound")?
            .call(&JsValue::undefined(), &[], ctx)
            .map_err(|e| e.to_string())?
            .as_object()
            .ok_or("reads missing")?
            .clone();
        let module = Module::parse(Source::from_bytes(source.as_bytes()), None, ctx)
            .map_err(|e| format!("SyntaxError: {e}"))?;
        let promise = module.load_link_evaluate(ctx);
        ctx.run_jobs().map_err(|e| e.to_string())?;
        match promise.state() {
            boa_engine::builtins::promise::PromiseState::Fulfilled(_) => {}
            boa_engine::builtins::promise::PromiseState::Rejected(err) => {
                let err = JsError::from_opaque(err);
                return Err(format!("module evaluation failed: {err}"));
            }
            boa_engine::builtins::promise::PromiseState::Pending => {
                return Err("module evaluation did not complete (top-level await is not supported)".into())
            }
        }
        let ns = module.namespace(ctx);
        let name = if entry.is_empty() || entry == "main" {
            // Prefer the default export, then a named `main`.
            let d = ns.get(js_string!("default"), ctx).map_err(|e| e.to_string())?;
            if d.is_callable() { d } else { ns.get(js_string!("main"), ctx).map_err(|e| e.to_string())? }
        } else {
            ns.get(JsString::from(entry), ctx).map_err(|e| e.to_string())?
        };
        let main = name
            .as_callable()
            .ok_or_else(|| format!("entry `{entry}` is not an exported function"))?
            .clone();
        st.main = Some(main);
        st.reads = Some(reads);
        Ok(())
}

fn run_impl(params: Vec<u8>) -> Result<Vec<u8>, u32> {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let st = guard.as_mut().ok_or(ST_INTERNAL)?;
            let ctx = &mut st.ctx;
            let p: Cbor = ciborium::from_reader(params.as_slice()).map_err(|_| ST_INTERNAL)?;
            let pjs = cbor_to_js(&p, ctx).map_err(|_| ST_INTERNAL)?;
            let (Some(main), Some(reads)) = (st.main.clone(), st.reads.clone()) else { return Err(ST_INTERNAL) };
            let res = main.call(&JsValue::undefined(), &[reads.into(), pjs], ctx);
            let res = match res {
                Ok(v) => v,
                Err(e) => {
                    let msg = e.to_string();
                    eprintln!("kernel error: {msg}");
                    return Err(status_from_error(&msg));
                }
            };
            // Resolve a returned promise (async main) by draining jobs.
            let res = if let Some(p) = res.as_promise() {
                ctx.run_jobs().map_err(|_| ST_INTERNAL)?;
                match p.state() {
                    boa_engine::builtins::promise::PromiseState::Fulfilled(v) => v,
                    boa_engine::builtins::promise::PromiseState::Rejected(e) => {
                        let msg = JsError::from_opaque(e).to_string();
                        eprintln!("kernel error: {msg}");
                        return Err(status_from_error(&msg));
                    }
                    _ => return Err(ST_INTERNAL),
                }
            } else {
                res
            };
            // Canonical result encoding: structural walk to CBOR (Date -> tag 1,
            // functions/undefined dropped). The host validates against the RT.
            let cbor = js_to_cbor(&res, ctx).map_err(|_| ST_INTERNAL)?;
            let mut out = Vec::new();
            ciborium::into_writer(&cbor, &mut out).map_err(|_| ST_INTERNAL)?;
            Ok(out)
        })
}

fn status_from_error(msg: &str) -> u32 {
    if msg.contains("RemitError: row-cap") || msg.contains("RemitError: call-cap") {
        ST_LIMIT
    } else if msg.contains("RemitError: denied") {
        ST_DENIED
    } else {
        ST_INTERNAL
    }
}

fn remit_err(code: data::ErrorCode) -> JsError {
    let c = match code {
        data::ErrorCode::RowCap => "row-cap",
        data::ErrorCode::CallCap => "call-cap",
        data::ErrorCode::ParamType => "param-type",
        data::ErrorCode::Denied => "denied",
        data::ErrorCode::Internal => "internal",
    };
    JsNativeError::error().with_message(format!("RemitError: {c}")).into()
}

fn install_natives(ctx: &mut Context) -> JsResult<()> {
    ctx.register_global_callable(
        js_string!("__remit_declared"),
        0,
        NativeFunction::from_fn_ptr(|_, _, ctx| {
            let names = data::declared();
            let arr = JsArray::from_iter(names.into_iter().map(|n| JsValue::from(JsString::from(n.as_str()))), ctx);
            Ok(arr.into())
        }),
    )?;
    ctx.register_global_callable(
        js_string!("__remit_call"),
        2,
        NativeFunction::from_fn_ptr(|_, args, ctx| {
            let name = args
                .first()
                .and_then(|v| v.as_string())
                .ok_or_else(|| JsNativeError::typ().with_message("read name"))?
                .to_std_string_escaped();
            let params = args.get(1).cloned().unwrap_or_default();
            let cbor = js_to_cbor(&params, ctx)?;
            let mut buf = Vec::new();
            ciborium::into_writer(&cbor, &mut buf)
                .map_err(|_| JsNativeError::typ().with_message("params"))?;
            let table = BOUND.with(|b| {
                let mut b = b.borrow_mut();
                if !b.contains_key(&name) {
                    match data::bind(&name) {
                        Some(r) => {
                            b.insert(name.clone(), r);
                        }
                        None => return Err(JsNativeError::reference().with_message(format!("no read `{name}`")).into()),
                    }
                }
                b[&name].call(&buf).map_err(remit_err)
            })?;
            table_to_js(&table, ctx)
        }),
    )?;
    ctx.register_global_callable(
        js_string!("__remit_col"),
        2,
        NativeFunction::from_fn_ptr(|_, args, ctx| {
            let id = args.first().and_then(|v| v.as_number()).unwrap_or(-1.0) as usize;
            let col = args.get(1).and_then(|v| v.as_number()).unwrap_or(-1.0) as usize;
            let vals = TABLES.with(|t| {
                let t = t.borrow();
                let (batches, n) = t.get(id)?;
                let mut vals: Vec<JsValue> = Vec::with_capacity(*n);
                for b in batches {
                    if col >= b.num_columns() {
                        return None;
                    }
                    push_values(b.column(col), &mut vals);
                }
                Some(vals)
            });
            let vals = vals.ok_or_else(|| JsNativeError::typ().with_message("column"))?;
            Ok(JsArray::from_iter(vals, ctx).into())
        }),
    )?;
    ctx.register_global_callable(
        js_string!("__remit_fn"),
        2,
        NativeFunction::from_fn_ptr(|_, args, ctx| {
            let name = args
                .first()
                .and_then(|v| v.as_string())
                .ok_or_else(|| JsNativeError::typ().with_message("function name"))?
                .to_std_string_escaped();
            let a = args.get(1).cloned().unwrap_or_default();
            let cbor = js_to_cbor(&a, ctx)?;
            let mut buf = Vec::new();
            ciborium::into_writer(&cbor, &mut buf).map_err(|_| JsNativeError::typ().with_message("args"))?;
            let out = holder_fns::call(&name, &buf).map_err(remit_err)?;
            let v: Cbor = ciborium::from_reader(out.as_slice()).map_err(|_| JsNativeError::typ().with_message("result"))?;
            cbor_to_js(&v, ctx)
        }),
    )?;
    Ok(())
}

/// Decode the table's Arrow IPC batches into a columnar JS object:
/// `{ id, names, types, n }` (columns are fetched lazily by `__remit_col`). Timestamps/dates become epoch ms numbers;
/// the prelude turns them into Dates in `rows()`.
fn table_to_js(table: &data::Table, ctx: &mut Context) -> JsResult<JsValue> {
    let schema_bytes = table.schema();
    let mut batches: Vec<RecordBatch> = Vec::new();
    let mut stream = schema_bytes.clone();
    while let Some(b) = table.next_batch() {
        stream.extend_from_slice(&b);
    }
    let reader = arrow_ipc::reader::StreamReader::try_new(std::io::Cursor::new(stream), None)
        .map_err(|e| JsNativeError::typ().with_message(format!("arrow: {e}")))?;
    let schema = reader.schema();
    for b in reader {
        batches.push(b.map_err(|e| JsNativeError::typ().with_message(format!("arrow: {e}")))?);
    }
    let mut names = Vec::new();
    let mut types = Vec::new();
    let mut n = 0usize;
    for b in &batches {
        n += b.num_rows();
    }
    for f in schema.fields().iter() {
        names.push(JsValue::from(JsString::from(f.name().as_str())));
        let kind = kind_of(f.data_type());
        types.push(JsValue::from(JsString::from(kind)));
    }
    let id = TABLES.with(|t| {
        let mut t = t.borrow_mut();
        t.push((batches, n));
        t.len() - 1
    });
    let obj = JsObject::with_object_proto(ctx.intrinsics());
    obj.set(js_string!("names"), JsArray::from_iter(names, ctx), false, ctx)?;
    obj.set(js_string!("types"), JsArray::from_iter(types, ctx), false, ctx)?;
    obj.set(js_string!("id"), id as f64, false, ctx)?;
    obj.set(js_string!("n"), n as f64, false, ctx)?;
    Ok(obj.into())
}

fn kind_of(dt: &DataType) -> &'static str {
    match dt {
        DataType::Boolean => "bool",
        DataType::Int8 | DataType::Int16 | DataType::Int32 | DataType::Int64
        | DataType::UInt8 | DataType::UInt16 | DataType::UInt32 | DataType::UInt64 => "int",
        DataType::Float16 | DataType::Float32 | DataType::Float64 | DataType::Decimal128(_, _) => "float",
        DataType::Timestamp(_, _) => "timestamp",
        DataType::Date32 | DataType::Date64 => "date",
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => "string",
        _ => "other",
    }
}

fn push_values(a: &ArrayRef, out: &mut Vec<JsValue>) {
    macro_rules! prim {
        ($t:ty) => {{
            let arr = a.as_primitive::<$t>();
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(arr.value(i) as f64) });
            }
        }};
    }
    match a.data_type() {
        DataType::Boolean => {
            let arr = a.as_boolean();
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(arr.value(i)) });
            }
        }
        DataType::Int8 => prim!(Int8Type),
        DataType::Int16 => prim!(Int16Type),
        DataType::Int32 => prim!(Int32Type),
        DataType::Int64 => prim!(Int64Type),
        DataType::UInt8 => prim!(UInt8Type),
        DataType::UInt16 => prim!(UInt16Type),
        DataType::UInt32 => prim!(UInt32Type),
        DataType::UInt64 => prim!(UInt64Type),
        DataType::Float32 => prim!(Float32Type),
        DataType::Float64 => prim!(Float64Type),
        DataType::Decimal128(_, scale) => {
            let arr = a.as_primitive::<Decimal128Type>();
            let div = 10f64.powi(*scale as i32);
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(arr.value(i) as f64 / div) });
            }
        }
        DataType::Timestamp(unit, _) => {
            let div = match unit {
                TimeUnit::Second => 1e-3,
                TimeUnit::Millisecond => 1.0,
                TimeUnit::Microsecond => 1e3,
                TimeUnit::Nanosecond => 1e6,
            };
            macro_rules! ts {
                ($t:ty) => {{
                    let arr = a.as_primitive::<$t>();
                    for i in 0..arr.len() {
                        out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from((arr.value(i) as f64 / div).floor()) });
                    }
                }};
            }
            match unit {
                TimeUnit::Second => ts!(TimestampSecondType),
                TimeUnit::Millisecond => ts!(TimestampMillisecondType),
                TimeUnit::Microsecond => ts!(TimestampMicrosecondType),
                TimeUnit::Nanosecond => ts!(TimestampNanosecondType),
            }
        }
        DataType::Date32 => {
            let arr = a.as_primitive::<Date32Type>();
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(arr.value(i) as f64 * 86_400_000.0) });
            }
        }
        DataType::Date64 => prim!(Date64Type),
        DataType::Utf8 => {
            let arr = a.as_string::<i32>();
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(JsString::from(arr.value(i))) });
            }
        }
        DataType::LargeUtf8 => {
            let arr = a.as_string::<i64>();
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(JsString::from(arr.value(i))) });
            }
        }
        DataType::Utf8View => {
            let arr = a.as_string_view();
            for i in 0..arr.len() {
                out.push(if arr.is_null(i) { JsValue::null() } else { JsValue::from(JsString::from(arr.value(i))) });
            }
        }
        _ => {
            for _ in 0..a.len() {
                out.push(JsValue::null());
            }
        }
    }
}

/// CBOR -> JS. Tag 1 (epoch seconds) becomes a Date.
fn cbor_to_js(v: &Cbor, ctx: &mut Context) -> JsResult<JsValue> {
    Ok(match v {
        Cbor::Null => JsValue::null(),
        Cbor::Bool(b) => JsValue::from(*b),
        Cbor::Integer(i) => JsValue::from(i128::from(*i) as f64),
        Cbor::Float(f) => JsValue::from(*f),
        Cbor::Text(s) => JsValue::from(JsString::from(s.as_str())),
        Cbor::Bytes(b) => JsArray::from_iter(b.iter().map(|x| JsValue::from(*x as f64)), ctx).into(),
        Cbor::Array(a) => {
            let mut vals = Vec::with_capacity(a.len());
            for x in a {
                vals.push(cbor_to_js(x, ctx)?);
            }
            JsArray::from_iter(vals, ctx).into()
        }
        Cbor::Map(m) => {
            let obj = JsObject::with_object_proto(ctx.intrinsics());
            for (k, val) in m {
                let key = match k {
                    Cbor::Text(s) => s.clone(),
                    _ => continue,
                };
                let jv = cbor_to_js(val, ctx)?;
                obj.set(JsString::from(key.as_str()), jv, false, ctx)?;
            }
            obj.into()
        }
        Cbor::Tag(1, inner) => {
            let secs = match inner.as_ref() {
                Cbor::Integer(i) => i128::from(*i) as f64,
                Cbor::Float(f) => *f,
                _ => f64::NAN,
            };
            let date_ctor = ctx.intrinsics().constructors().date().constructor();
            date_ctor
                .construct(&[JsValue::from((secs * 1000.0).round())], None, ctx)?
                .into()
        }
        Cbor::Tag(_, inner) => cbor_to_js(inner, ctx)?,
        _ => JsValue::undefined(),
    })
}

/// JS -> CBOR for read params. Dates become tag 1; everything else via
/// JSON-like structural walk.
fn js_to_cbor(v: &JsValue, ctx: &mut Context) -> JsResult<Cbor> {
    if v.is_null_or_undefined() {
        return Ok(Cbor::Null);
    }
    if let Some(b) = v.as_boolean() {
        return Ok(Cbor::Bool(b));
    }
    if let Some(n) = v.as_number() {
        if n.fract() == 0.0 && n.abs() < 9.0e15 {
            return Ok(Cbor::Integer((n as i64).into()));
        }
        return Ok(Cbor::Float(n));
    }
    if let Some(s) = v.as_string() {
        return Ok(Cbor::Text(s.to_std_string_escaped()));
    }
    if let Some(o) = v.as_object() {
        if o.is::<boa_engine::builtins::date::Date>() {
            let ms = o
                .get(js_string!("getTime"), ctx)?
                .as_callable()
                .ok_or_else(|| JsNativeError::typ().with_message("date"))?
                .call(v, &[], ctx)?
                .to_number(ctx)?;
            return Ok(Cbor::Tag(1, Box::new(Cbor::Float(ms / 1000.0))));
        }
        if o.is_array() {
            let len = o.get(js_string!("length"), ctx)?.to_length(ctx)?;
            let mut out = Vec::with_capacity(len as usize);
            for i in 0..len {
                out.push(js_to_cbor(&o.get(i, ctx)?, ctx)?);
            }
            return Ok(Cbor::Array(out));
        }
        let keys = o.own_property_keys(ctx)?;
        let mut m = Vec::new();
        for k in keys {
            if let PropertyKey::String(s) = &k {
                let val = o.get(k.clone(), ctx)?;
                if val.is_undefined() || val.is_callable() {
                    continue;
                }
                m.push((Cbor::Text(s.to_std_string_escaped()), js_to_cbor(&val, ctx)?));
            }
        }
        return Ok(Cbor::Map(m));
    }
    Ok(Cbor::Null)
}

export!(Engine);
