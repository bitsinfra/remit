//! Remit emit plane (trusted, main process):
//! decode → validate against the RT type → trusted transforms (quantize,
//! clamp, DP noise) → encode. A violation releases nothing.

pub mod dp;

use remit_types::{Rt, Violation};
use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum EmitError {
    #[error("type violation: {0}")]
    TypeViolation(Violation),
    #[error("encoded result is {0} bytes, above output_bytes {1}")]
    OutputTooLarge(usize, u64),
    #[error("kernel output is not valid CBOR")]
    Decode,
}

impl EmitError {
    /// Status reported to the Sender.
    pub fn status(&self) -> &'static str {
        match self {
            EmitError::TypeViolation(_) | EmitError::Decode => "type_violation",
            EmitError::OutputTooLarge(_, _) => "limit_exceeded",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Emitted {
    /// Normalized value (what the Sender receives).
    pub value: Value,
    /// Canonical JSON encoding (JCS) of `value`.
    pub encoded: Vec<u8>,
    pub result_sha256: String,
}

/// Decode a kernel's CBOR output (tag 1 → RFC 3339).
pub fn decode_kernel(cbor: &[u8]) -> Result<Value, EmitError> {
    let v: ciborium::Value = ciborium::from_reader(cbor).map_err(|_| EmitError::Decode)?;
    Ok(cbor_to_json(&v))
}

fn cbor_to_json(v: &ciborium::Value) -> Value {
    use ciborium::Value as C;
    match v {
        C::Null => Value::Null,
        C::Bool(b) => Value::Bool(*b),
        C::Integer(i) => {
            let n = i128::from(*i);
            i64::try_from(n)
                .map(Value::from)
                .unwrap_or_else(|_| Value::from(n as f64))
        }
        C::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        C::Text(s) => Value::String(s.clone()),
        C::Bytes(b) => Value::Array(b.iter().map(|x| Value::from(*x)).collect()),
        C::Array(a) => Value::Array(a.iter().map(cbor_to_json).collect()),
        C::Map(m) => Value::Object(
            m.iter()
                .filter_map(|(k, v)| match k {
                    C::Text(k) => Some((k.clone(), cbor_to_json(v))),
                    _ => None,
                })
                .collect(),
        ),
        C::Tag(1, inner) => {
            let secs = match inner.as_ref() {
                C::Integer(i) => i128::from(*i) as f64,
                C::Float(f) => *f,
                _ => f64::NAN,
            };
            if secs.is_finite() {
                Value::String(remit_types::format_timestamp_ms(
                    (secs * 1000.0).round() as i64
                ))
            } else {
                Value::Null
            }
        }
        C::Tag(_, inner) => cbor_to_json(inner),
        _ => Value::Null,
    }
}

/// Shape query-mode rows to the declared type: list/table → rows; struct →
/// the single row; scalar → the single cell.
pub fn shape_rows(rt: &Rt, rows: Vec<Value>) -> Value {
    match rt {
        Rt::List { .. } | Rt::Table { .. } => Value::Array(rows),
        Rt::Struct { .. } => match rows.len() {
            1 => rows.into_iter().next().unwrap(),
            _ => Value::Array(rows), // fails validation: exactly one row expected
        },
        Rt::Optional(inner) => {
            if rows.is_empty() {
                Value::Null
            } else {
                shape_rows(inner, rows)
            }
        }
        _ => {
            if rows.len() == 1 {
                if let Value::Object(o) = &rows[0] {
                    if o.len() == 1 {
                        return o.values().next().cloned().unwrap();
                    }
                }
            }
            Value::Array(rows)
        }
    }
}

/// Column layout of a `table<struct>` result (for Arrow IPC encoding).
pub fn table_layout(rt: &Rt) -> Option<Vec<(String, String)>> {
    let Rt::Table { of, .. } = rt else {
        return None;
    };
    let Rt::Struct { fields } = of.as_ref() else {
        return None;
    };
    Some(
        fields
            .iter()
            .map(|(n, t)| {
                let t = match t {
                    Rt::Optional(i) => i.as_ref(),
                    t => t,
                };
                let k = match t {
                    Rt::Bool => "bool",
                    Rt::Int { .. } => "int",
                    Rt::Float { .. } | Rt::Decimal { .. } => "float",
                    Rt::Timestamp { .. } => "timestamp",
                    Rt::Date { .. } => "date",
                    _ => "string",
                };
                (n.clone(), k.to_string())
            })
            .collect(),
    )
}

/// Clamp the numeric fields of a released DP row to the declared bounds
/// (post-processing: costs no privacy).
pub fn clamp_row(rt: &Rt, row: Value) -> Value {
    match (rt, row) {
        (Rt::List { of, .. } | Rt::Table { of, .. }, v @ Value::Object(_)) => clamp_row(of, v),
        (Rt::Optional(of), v) if !v.is_null() => clamp_row(of, v),
        (Rt::Struct { fields }, Value::Object(mut o)) => {
            for (n, t) in fields {
                if let Some(v) = o.get_mut(n) {
                    *v = clamp_row(t, v.take());
                }
            }
            Value::Object(o)
        }
        // A scalar result over a one-column row.
        (Rt::Int { .. } | Rt::Float { .. } | Rt::Decimal { .. }, Value::Object(o)) => {
            Value::Object(o.into_iter().map(|(k, v)| (k, clamp_row(rt, v))).collect())
        }
        (Rt::Int { min, max }, Value::Number(n)) => match n.as_i64() {
            Some(i) => Value::from(i.clamp(*min, *max)),
            None => n
                .as_f64()
                .map(|f| Value::from((f.round() as i64).clamp(*min, *max)))
                .unwrap_or(Value::Null),
        },
        (Rt::Float { min, max, .. } | Rt::Decimal { min, max, .. }, Value::Number(n)) => n
            .as_f64()
            .and_then(|f| serde_json::Number::from_f64(f.clamp(*min, *max)))
            .map(Value::Number)
            .unwrap_or(Value::Null),
        (_, v) => v,
    }
}

/// Validate, transform and encode.
pub fn emit(rt: &Rt, value: &Value, output_bytes: u64) -> Result<Emitted, EmitError> {
    let v = rt.validate(value).map_err(EmitError::TypeViolation)?;
    let encoded = remit_wire::jcs::canonical_bytes(&v).map_err(|_| EmitError::Decode)?;
    if encoded.len() as u64 > output_bytes {
        return Err(EmitError::OutputTooLarge(encoded.len(), output_bytes));
    }
    let result_sha256 = format!("sha256:{}", remit_wire::sha256_hex(&encoded));
    Ok(Emitted {
        value: v,
        encoded,
        result_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_and_emits() {
        let rt = Rt::from_json(
            &json!({"list": {"max": 2, "of": {"struct": {"n": {"int": {"min": 0, "max": 10}}}}}}),
        )
        .unwrap();
        let v = shape_rows(&rt, vec![json!({"n": 3})]);
        let e = emit(&rt, &v, 100).unwrap();
        assert_eq!(e.encoded, b"[{\"n\":3}]");
        assert!(e.result_sha256.starts_with("sha256:"));
        assert!(matches!(
            emit(&rt, &json!([{"n": 11}]), 100),
            Err(EmitError::TypeViolation(_))
        ));
        assert!(matches!(
            emit(&rt, &json!([{"n": 1}, {"n": 1}]), 5),
            Err(EmitError::OutputTooLarge(_, 5))
        ));
        let scalar = Rt::from_json(&json!({"int": {"min": 0, "max": 10}})).unwrap();
        assert_eq!(shape_rows(&scalar, vec![json!({"count": 4})]), json!(4));
    }

    #[test]
    fn kernel_cbor() {
        use ciborium::Value as C;
        let mut b = Vec::new();
        ciborium::into_writer(
            &C::Array(vec![C::Map(vec![(
                C::Text("t".into()),
                C::Tag(1, Box::new(C::Float(1795000000.5))),
            )])]),
            &mut b,
        )
        .unwrap();
        assert_eq!(
            decode_kernel(&b).unwrap(),
            json!([{"t": "2026-11-18T11:06:40.500Z"}])
        );
        assert!(decode_kernel(&[0xff, 0x00]).is_err());
    }
}
