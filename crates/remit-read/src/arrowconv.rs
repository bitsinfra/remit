//! Arrow conversions: batches → JSON rows (emit plane), Arrow IPC framing
//! for the kernel handoff, JSON params → DataFusion scalars.

use datafusion::arrow::array::{Array, AsArray};
use datafusion::arrow::datatypes::*;
use datafusion::arrow::ipc::writer::{
    write_message, DictionaryTracker, IpcDataGenerator, IpcWriteOptions,
};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::scalar::ScalarValue;
use remit_types::{format_date_days, format_timestamp_ms, parse_date_days, parse_timestamp_ms};
use remit_wire::ParamType;
use serde_json::{Map, Value};

/// Convert record batches to JSON objects (one per row).
pub fn batches_to_rows(batches: &[RecordBatch]) -> Vec<Value> {
    let mut out = Vec::new();
    for b in batches {
        let schema = b.schema();
        for r in 0..b.num_rows() {
            let mut m = Map::new();
            for (i, f) in schema.fields().iter().enumerate() {
                m.insert(f.name().clone(), cell(b.column(i).as_ref(), r));
            }
            out.push(Value::Object(m));
        }
    }
    out
}

/// Single-row, single-column result as a scalar JSON value.
pub fn cell(a: &dyn Array, r: usize) -> Value {
    if a.is_null(r) {
        return Value::Null;
    }
    macro_rules! num {
        ($t:ty) => {
            Value::from(a.as_primitive::<$t>().value(r))
        };
    }
    match a.data_type() {
        DataType::Boolean => Value::Bool(a.as_boolean().value(r)),
        DataType::Int8 => num!(Int8Type),
        DataType::Int16 => num!(Int16Type),
        DataType::Int32 => num!(Int32Type),
        DataType::Int64 => num!(Int64Type),
        DataType::UInt8 => num!(UInt8Type),
        DataType::UInt16 => num!(UInt16Type),
        DataType::UInt32 => num!(UInt32Type),
        DataType::UInt64 => num!(UInt64Type),
        DataType::Float32 => float(a.as_primitive::<Float32Type>().value(r) as f64),
        DataType::Float64 => float(a.as_primitive::<Float64Type>().value(r)),
        DataType::Decimal128(_, s) => {
            let v = a.as_primitive::<Decimal128Type>().value(r);
            float(v as f64 / 10f64.powi(*s as i32))
        }
        DataType::Utf8 => Value::String(a.as_string::<i32>().value(r).to_string()),
        DataType::LargeUtf8 => Value::String(a.as_string::<i64>().value(r).to_string()),
        DataType::Utf8View => Value::String(a.as_string_view().value(r).to_string()),
        DataType::Timestamp(u, _) => {
            let ms = match u {
                TimeUnit::Second => a.as_primitive::<TimestampSecondType>().value(r) * 1000,
                TimeUnit::Millisecond => a.as_primitive::<TimestampMillisecondType>().value(r),
                TimeUnit::Microsecond => a
                    .as_primitive::<TimestampMicrosecondType>()
                    .value(r)
                    .div_euclid(1000),
                TimeUnit::Nanosecond => a
                    .as_primitive::<TimestampNanosecondType>()
                    .value(r)
                    .div_euclid(1_000_000),
            };
            Value::String(format_timestamp_ms(ms))
        }
        DataType::Date32 => {
            Value::String(format_date_days(a.as_primitive::<Date32Type>().value(r)))
        }
        DataType::Date64 => Value::String(format_date_days(
            (a.as_primitive::<Date64Type>().value(r) / 86_400_000) as i32,
        )),
        DataType::Binary => Value::String(base64_encode(a.as_binary::<i32>().value(r))),
        _ => {
            let s =
                datafusion::arrow::util::display::array_value_to_string(a, r).unwrap_or_default();
            Value::String(s)
        }
    }
}

fn float(f: f64) -> Value {
    serde_json::Number::from_f64(f)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn base64_encode(b: &[u8]) -> String {
    use std::fmt::Write;
    // Minimal standard base64 (avoid an extra dep here).
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.write_char(T[(n >> (18 - 6 * i) & 63) as usize] as char)
                    .unwrap();
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Arrow IPC schema message (no EOS), so `schema ‖ batch*` is a valid stream.
pub fn ipc_schema_message(schema: &Schema) -> Vec<u8> {
    let gen = IpcDataGenerator::default();
    let mut tracker = DictionaryTracker::new(false);
    let opts = IpcWriteOptions::default();
    let enc = gen.schema_to_bytes_with_dictionary_tracker(schema, &mut tracker, &opts);
    let mut buf = Vec::new();
    write_message(&mut buf, enc, &opts).expect("ipc schema");
    buf
}

/// Arrow IPC record-batch message(s) (no EOS).
#[allow(deprecated)]
pub fn ipc_batch_message(batch: &RecordBatch) -> Vec<u8> {
    let gen = IpcDataGenerator::default();
    let mut tracker = DictionaryTracker::new(false);
    let opts = IpcWriteOptions::default();
    let (dicts, enc) = gen
        .encoded_batch(batch, &mut tracker, &opts)
        .expect("ipc batch");
    let mut buf = Vec::new();
    for d in dicts {
        write_message(&mut buf, d, &opts).expect("ipc dict");
    }
    write_message(&mut buf, enc, &opts).expect("ipc batch");
    buf
}

/// Full Arrow IPC stream (schema, batches, EOS) for `table<…>` results.
pub fn ipc_stream(schema: &Schema, batches: &[RecordBatch]) -> Vec<u8> {
    let mut w =
        datafusion::arrow::ipc::writer::StreamWriter::try_new(Vec::new(), schema).expect("ipc");
    for b in batches {
        w.write(b).expect("ipc");
    }
    w.finish().expect("ipc");
    w.into_inner().expect("ipc")
}

/// JSON param → DataFusion scalar of the declared type. Timestamps are
/// normalized to millisecond UTC to match the policy views.
pub fn param_scalar(v: &Value, t: ParamType) -> Option<ScalarValue> {
    Some(match t {
        ParamType::Timestamp => {
            let ms = match v {
                Value::String(s) => parse_timestamp_ms(s)?,
                Value::Number(n) => n.as_i64()?,
                _ => return None,
            };
            ScalarValue::TimestampMillisecond(Some(ms), Some("UTC".into()))
        }
        ParamType::Date => ScalarValue::Date32(Some(parse_date_days(v.as_str()?)?)),
        ParamType::Int => ScalarValue::Int64(Some(
            v.as_i64()
                .or_else(|| v.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))?,
        )),
        ParamType::Float => ScalarValue::Float64(Some(v.as_f64()?)),
        ParamType::String => ScalarValue::Utf8(Some(v.as_str()?.to_string())),
        ParamType::Bool => ScalarValue::Boolean(Some(v.as_bool()?)),
    })
}

/// A placeholder value used for analysis when params are unknown.
pub fn param_placeholder(t: ParamType) -> ScalarValue {
    match t {
        ParamType::Timestamp => ScalarValue::TimestampMillisecond(None, Some("UTC".into())),
        ParamType::Date => ScalarValue::Date32(None),
        ParamType::Int => ScalarValue::Int64(None),
        ParamType::Float => ScalarValue::Float64(None),
        ParamType::String => ScalarValue::Utf8(None),
        ParamType::Bool => ScalarValue::Boolean(None),
    }
}

/// Map an Arrow type to the RT-ish kind used in catalogs and codegen.
pub fn kind_of(dt: &DataType) -> &'static str {
    match dt {
        DataType::Boolean => "bool",
        DataType::Int8
        | DataType::Int16
        | DataType::Int32
        | DataType::Int64
        | DataType::UInt8
        | DataType::UInt16
        | DataType::UInt32
        | DataType::UInt64 => "int",
        DataType::Float16 | DataType::Float32 | DataType::Float64 | DataType::Decimal128(_, _) => {
            "float"
        }
        DataType::Timestamp(_, _) => "timestamp",
        DataType::Date32 | DataType::Date64 => "date",
        DataType::Binary | DataType::LargeBinary => "bytes",
        _ => "string",
    }
}

/// JSON rows → one record batch with the given `(column, kind)` layout (kinds
/// as produced by [`kind_of`]). Used to hand noisy DP rows to kernels and to
/// encode `table<…>` results as Arrow IPC.
pub fn rows_to_batch(rows: &[Value], cols: &[(String, String)]) -> RecordBatch {
    use datafusion::arrow::array::*;
    use std::sync::Arc;
    let mut fields = Vec::new();
    let mut arrays: Vec<ArrayRef> = Vec::new();
    for (name, kind) in cols {
        let get = |r: &Value| r.get(name.as_str()).cloned().unwrap_or(Value::Null);
        let (dt, arr): (DataType, ArrayRef) = match kind.as_str() {
            "bool" => (
                DataType::Boolean,
                Arc::new(
                    rows.iter()
                        .map(|r| get(r).as_bool())
                        .collect::<BooleanArray>(),
                ),
            ),
            "int" => (
                DataType::Int64,
                Arc::new(rows.iter().map(|r| get(r).as_i64()).collect::<Int64Array>()),
            ),
            "float" => (
                DataType::Float64,
                Arc::new(
                    rows.iter()
                        .map(|r| get(r).as_f64())
                        .collect::<Float64Array>(),
                ),
            ),
            "timestamp" => (
                DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                Arc::new(
                    rows.iter()
                        .map(|r| get(r).as_str().and_then(parse_timestamp_ms))
                        .collect::<TimestampMillisecondArray>()
                        .with_timezone("UTC"),
                ),
            ),
            "date" => (
                DataType::Date32,
                Arc::new(
                    rows.iter()
                        .map(|r| get(r).as_str().and_then(parse_date_days))
                        .collect::<Date32Array>(),
                ),
            ),
            _ => (
                DataType::Utf8,
                Arc::new(
                    rows.iter()
                        .map(|r| match get(r) {
                            Value::Null => None,
                            Value::String(s) => Some(s),
                            v => Some(v.to_string()),
                        })
                        .collect::<StringArray>(),
                ),
            ),
        };
        fields.push(Field::new(name, dt, true));
        arrays.push(arr);
    }
    let schema = Arc::new(Schema::new(fields));
    RecordBatch::try_new_with_options(
        schema,
        arrays,
        &RecordBatchOptions::new().with_row_count(Some(rows.len())),
    )
    .expect("uniform columns")
}

#[cfg(test)]
mod tests {
    #[test]
    fn b64() {
        assert_eq!(super::base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(super::base64_encode(b"hi!"), "aGkh");
    }
}
