//! Validator + trusted transforms. `validate` returns the *normalized* value
//! (quantized to precision/granularity), which is what gets encoded. A
//! violation means no partial result is released.

use base64::Engine as _;
use serde_json::{Map, Value};

use crate::parse::escape_ptr;
use crate::{format_date_days, format_timestamp_ms, parse_date_days, parse_timestamp_ms, Rt};

/// A value that does not inhabit its declared type. Holder-side detail only:
/// Senders see just `type_violation`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{path}: {reason}")]
pub struct Violation {
    pub path: String,
    pub reason: String,
}

fn v(path: &str, reason: impl Into<String>) -> Violation {
    Violation {
        path: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        reason: reason.into(),
    }
}

fn type_name(x: &Value) -> &'static str {
    match x {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl Rt {
    /// Validate `value` and return its normalized form.
    pub fn validate(&self, value: &Value) -> Result<Value, Violation> {
        let mut budget = 0u64;
        self.validate_at(value, "", &mut budget)
    }

    fn validate_at(&self, x: &Value, path: &str, nodes: &mut u64) -> Result<Value, Violation> {
        *nodes += 1;
        if *nodes > 50_000_000 {
            return Err(v(path, "value too large"));
        }
        match self {
            Rt::Bool => match x {
                Value::Bool(_) => Ok(x.clone()),
                _ => Err(v(path, format!("expected bool, got {}", type_name(x)))),
            },
            Rt::Int { min, max } => {
                let n = match x {
                    Value::Number(n) => n.as_i64().or_else(|| {
                        n.as_f64()
                            .filter(|f| f.fract() == 0.0 && f.abs() < 9.007e15)
                            .map(|f| f as i64)
                    }),
                    _ => None,
                }
                .ok_or_else(|| v(path, format!("expected integer, got {}", type_name(x))))?;
                if n < *min || n > *max {
                    return Err(v(path, format!("{n} outside [{min}, {max}]")));
                }
                Ok(Value::from(n))
            }
            Rt::Float {
                min,
                max,
                precision,
            } => {
                let f = x.as_f64().filter(|f| f.is_finite()).ok_or_else(|| {
                    v(
                        path,
                        format!("expected finite number, got {}", type_name(x)),
                    )
                })?;
                if f < *min || f > *max {
                    return Err(v(path, format!("{f} outside [{min}, {max}]")));
                }
                let q = match precision {
                    Some(p) => {
                        // Quantize onto the grid anchored at `min`. The step index,
                        // not the value, is clamped: clamping the value to an
                        // off-grid `max` would add one value beyond capacity.
                        let last = ((max - min) / p + 1e-9).floor();
                        let k = ((f - min) / p).round().min(last);
                        let q = (min + k * p).clamp(*min, *max);
                        // Trim representation noise (0.30000000000000004 → 0.3)
                        // when that names the same grid point.
                        let digits = (-p.log10()).ceil().max(0.0) as i32 + 1;
                        let s = 10f64.powi(digits.min(15));
                        let t = (q * s).round() / s;
                        if t >= *min && t <= *max && (t - q).abs() <= p * 1e-6 {
                            t
                        } else {
                            q
                        }
                    }
                    None => f,
                };
                Ok(serde_json::Number::from_f64(q)
                    .map(Value::Number)
                    .unwrap_or(Value::Null))
            }
            Rt::Decimal { scale, min, max } => {
                let f = match x {
                    Value::Number(n) => n.as_f64(),
                    Value::String(s) => s.parse::<f64>().ok(),
                    _ => None,
                }
                .filter(|f| f.is_finite())
                .ok_or_else(|| v(path, format!("expected decimal, got {}", type_name(x))))?;
                if f < *min || f > *max {
                    return Err(v(path, format!("{f} outside [{min}, {max}]")));
                }
                let s = 10f64.powi(*scale as i32);
                // Only grid points inside the range are representable.
                let (lo, hi) = ((min * s - 1e-9).ceil(), (max * s + 1e-9).floor());
                if lo > hi {
                    return Err(v(
                        path,
                        "no value of this scale lies inside the declared range",
                    ));
                }
                // `+ 0.0` folds negative zero, which would print as a second zero.
                let q = (f * s).round().clamp(lo, hi) / s + 0.0;
                Ok(Value::String(format!("{:.*}", *scale as usize, q)))
            }
            Rt::Enum { values } => match x {
                Value::String(s) if values.iter().any(|e| e == s) => Ok(x.clone()),
                Value::String(s) => Err(v(
                    path,
                    format!("`{s}` is not one of the declared enum values"),
                )),
                _ => Err(v(
                    path,
                    format!("expected enum string, got {}", type_name(x)),
                )),
            },
            Rt::String {
                max_len,
                charset,
                pattern,
            } => {
                let s = x
                    .as_str()
                    .ok_or_else(|| v(path, format!("expected string, got {}", type_name(x))))?;
                let n = s.chars().count();
                if n > *max_len as usize {
                    return Err(v(path, format!("string length {n} > max_len {max_len}")));
                }
                if let Some(c) = s.chars().find(|c| !charset.contains(*c)) {
                    return Err(v(
                        path,
                        format!("character {c:?} outside charset `{}`", charset.name()),
                    ));
                }
                if let Some(p) = pattern {
                    let re = regex::Regex::new(&format!("^(?:{p})$"))
                        .map_err(|_| v(path, "bad pattern"))?;
                    if !re.is_match(s) {
                        return Err(v(path, "string does not match pattern"));
                    }
                }
                Ok(x.clone())
            }
            Rt::Timestamp {
                min,
                max,
                granularity_ms,
            } => {
                let ms = match x {
                    Value::String(s) => parse_timestamp_ms(s),
                    Value::Number(n) => n.as_i64(),
                    _ => None,
                }
                .ok_or_else(|| {
                    v(
                        path,
                        format!("expected RFC 3339 timestamp, got {}", type_name(x)),
                    )
                })?;
                if ms < *min || ms > *max {
                    return Err(v(
                        path,
                        format!(
                            "{} outside [{}, {}]",
                            format_timestamp_ms(ms),
                            format_timestamp_ms(*min),
                            format_timestamp_ms(*max)
                        ),
                    ));
                }
                // Floor onto the grid anchored at `min`.
                let q = min + ((ms - min) / granularity_ms) * granularity_ms;
                Ok(Value::String(format_timestamp_ms(q)))
            }
            Rt::Date {
                min,
                max,
                granularity_days,
            } => {
                let d = match x {
                    Value::String(s) => parse_date_days(s.get(..10).unwrap_or(s)),
                    _ => None,
                }
                .ok_or_else(|| {
                    v(
                        path,
                        format!("expected YYYY-MM-DD date, got {}", type_name(x)),
                    )
                })?;
                if d < *min || d > *max {
                    return Err(v(path, "date outside declared range"));
                }
                let q = min + ((d - min) / granularity_days) * granularity_days;
                Ok(Value::String(format_date_days(q)))
            }
            Rt::Bytes { max_len } => {
                let s = x
                    .as_str()
                    .ok_or_else(|| v(path, "expected base64 string"))?;
                let b = base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|_| v(path, "invalid base64"))?;
                if b.len() > *max_len as usize {
                    return Err(v(path, format!("{} bytes > max_len {max_len}", b.len())));
                }
                Ok(Value::String(
                    base64::engine::general_purpose::STANDARD.encode(b),
                ))
            }
            Rt::List { max, of } | Rt::Table { max_rows: max, of } => {
                let a = x
                    .as_array()
                    .ok_or_else(|| v(path, format!("expected array, got {}", type_name(x))))?;
                if a.len() > *max as usize {
                    return Err(v(path, format!("{} items > max {max}", a.len())));
                }
                let mut out = Vec::with_capacity(a.len());
                for (i, e) in a.iter().enumerate() {
                    out.push(of.validate_at(e, &format!("{path}/{i}"), nodes)?);
                }
                Ok(Value::Array(out))
            }
            Rt::Struct { fields } => {
                let o = x
                    .as_object()
                    .ok_or_else(|| v(path, format!("expected object, got {}", type_name(x))))?;
                if let Some(k) = o.keys().find(|k| !fields.iter().any(|(f, _)| f == *k)) {
                    return Err(v(path, format!("undeclared field `{k}`")));
                }
                let mut out = Map::new();
                for (k, t) in fields {
                    let p = format!("{path}/{}", escape_ptr(k));
                    match o.get(k) {
                        Some(val) => {
                            out.insert(k.clone(), t.validate_at(val, &p, nodes)?);
                        }
                        None if matches!(t, Rt::Optional(_)) => {
                            out.insert(k.clone(), Value::Null);
                        }
                        None => return Err(v(&p, "missing field")),
                    }
                }
                Ok(Value::Object(out))
            }
            Rt::Optional(t) => match x {
                Value::Null => Ok(Value::Null),
                _ => t.validate_at(x, path, nodes),
            },
        }
    }
}
