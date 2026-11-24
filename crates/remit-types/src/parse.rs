//! Wire parsing, serialization and param binding for Remit Types.

use serde_json::{json, Map, Value};

use crate::{
    parse_duration_ms, Bound, Charset, Rt, RtTemplate, TypeError, MAX_ENUM, MAX_LEN, MAX_LIST,
    MAX_TIME_MS,
};

pub const E_UNBOUNDED: &str = "RMT-E0101";
pub const E_UNKNOWN_TYPE: &str = "RMT-E0102";
pub const E_BAD_BOUND: &str = "RMT-E0103";
pub const E_UNRESOLVED: &str = "RMT-E0104";
pub const E_EMPTY_RANGE: &str = "RMT-E0105";
pub const E_TOO_LARGE: &str = "RMT-E0106";
pub const E_GRANULARITY: &str = "RMT-E0107";

fn bound(v: Option<&Value>, path: &str, field: &str) -> Result<Bound, TypeError> {
    match v {
        None | Some(Value::Null) => Err(TypeError::new(
            &format!("{path}/{field}"),
            E_UNBOUNDED,
            format!("`{field}` is required: every Remit Type must be bounded"),
        )),
        Some(Value::String(s)) if s.starts_with('$') => Ok(Bound::Param(s[1..].to_string())),
        Some(v) => Ok(Bound::Lit(v.clone())),
    }
}

fn opt_bound(v: Option<&Value>) -> Option<Bound> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.starts_with('$') => Some(Bound::Param(s[1..].to_string())),
        Some(v) => Some(Bound::Lit(v.clone())),
    }
}

fn body<'a>(v: &'a Value, path: &str, ty: &str) -> Result<&'a Map<String, Value>, TypeError> {
    v.as_object().ok_or_else(|| {
        TypeError::new(
            path,
            E_BAD_BOUND,
            format!("`{ty}` expects an object of constraints"),
        )
    })
}

impl RtTemplate {
    /// Parse the wire (JSON) form. `path` is a JSON pointer prefix for diagnostics.
    pub fn from_json(v: &Value) -> Result<Self, TypeError> {
        Self::parse_at(v, "")
    }

    fn parse_at(v: &Value, path: &str) -> Result<Self, TypeError> {
        if let Value::String(s) = v {
            return match s.as_str() {
                "bool" => Ok(RtTemplate::Bool),
                other => Err(TypeError::new(
                    path,
                    if matches!(
                        other,
                        "int"
                            | "float"
                            | "string"
                            | "list"
                            | "timestamp"
                            | "bytes"
                            | "decimal"
                            | "date"
                    ) {
                        E_UNBOUNDED
                    } else {
                        E_UNKNOWN_TYPE
                    },
                    format!("type `{other}` needs constraints, e.g. {{\"{other}\": {{…}}}}"),
                )),
            };
        }
        let obj = v.as_object().ok_or_else(|| {
            TypeError::new(
                path,
                E_UNKNOWN_TYPE,
                "a type is a string (`\"bool\"`) or a single-key object",
            )
        })?;
        if obj.len() != 1 {
            return Err(TypeError::new(
                path,
                E_UNKNOWN_TYPE,
                "a type object must have exactly one key (the type name)",
            ));
        }
        let (name, b) = obj.iter().next().unwrap();
        let p = format!("{path}/{name}");
        Ok(match name.as_str() {
            "bool" => RtTemplate::Bool,
            "int" => {
                let b = body(b, &p, name)?;
                RtTemplate::Int {
                    min: bound(b.get("min"), &p, "min")?,
                    max: bound(b.get("max"), &p, "max")?,
                }
            }
            "float" => {
                let b = body(b, &p, name)?;
                RtTemplate::Float {
                    min: bound(b.get("min"), &p, "min")?,
                    max: bound(b.get("max"), &p, "max")?,
                    precision: opt_bound(b.get("precision")),
                }
            }
            "decimal" => {
                let b = body(b, &p, name)?;
                let scale = b
                    .get("scale")
                    .and_then(Value::as_u64)
                    .filter(|s| *s <= 18)
                    .ok_or_else(|| {
                        TypeError::new(
                            &format!("{p}/scale"),
                            E_UNBOUNDED,
                            "`scale` (0..=18) is required",
                        )
                    })?;
                RtTemplate::Decimal {
                    scale: scale as u32,
                    min: bound(b.get("min"), &p, "min")?,
                    max: bound(b.get("max"), &p, "max")?,
                }
            }
            "enum" => {
                let arr = match b {
                    Value::Array(a) => a,
                    Value::Object(o) => o
                        .get("values")
                        .and_then(Value::as_array)
                        .ok_or_else(|| TypeError::new(&p, E_UNBOUNDED, "`enum` needs `values`"))?,
                    _ => {
                        return Err(TypeError::new(
                            &p,
                            E_UNBOUNDED,
                            "`enum` needs a list of values",
                        ))
                    }
                };
                let mut values = Vec::with_capacity(arr.len());
                for (i, x) in arr.iter().enumerate() {
                    let s = x.as_str().ok_or_else(|| {
                        TypeError::new(
                            &format!("{p}/{i}"),
                            E_BAD_BOUND,
                            "enum values must be strings",
                        )
                    })?;
                    if values.iter().any(|v: &String| v == s) {
                        return Err(TypeError::new(
                            &format!("{p}/{i}"),
                            E_BAD_BOUND,
                            format!("duplicate enum value `{s}`"),
                        ));
                    }
                    values.push(s.to_string());
                }
                if values.is_empty() || values.len() > MAX_ENUM {
                    return Err(TypeError::new(
                        &p,
                        E_TOO_LARGE,
                        "enum must have 1..=65536 values",
                    ));
                }
                RtTemplate::Enum { values }
            }
            "string" => {
                let b = body(b, &p, name)?;
                let charset = match b.get("charset") {
                    None => Charset::Unicode,
                    Some(Value::String(s)) => Charset::from_name(s).ok_or_else(|| {
                        TypeError::new(
                            &format!("{p}/charset"),
                            E_BAD_BOUND,
                            format!("unknown charset `{s}` (digits|hex|alpha|alnum|base64|ascii|unicode)"),
                        )
                    })?,
                    Some(_) => return Err(TypeError::new(&format!("{p}/charset"), E_BAD_BOUND, "charset must be a string")),
                };
                let pattern = match b.get("pattern") {
                    None => None,
                    Some(Value::String(s)) => {
                        regex::Regex::new(s).map_err(|e| {
                            TypeError::new(
                                &format!("{p}/pattern"),
                                E_BAD_BOUND,
                                format!("invalid pattern: {e}"),
                            )
                        })?;
                        Some(s.clone())
                    }
                    Some(_) => {
                        return Err(TypeError::new(
                            &format!("{p}/pattern"),
                            E_BAD_BOUND,
                            "pattern must be a string",
                        ))
                    }
                };
                RtTemplate::String {
                    max_len: bound(b.get("max_len"), &p, "max_len")?,
                    charset,
                    pattern,
                }
            }
            "timestamp" => {
                let b = body(b, &p, name)?;
                RtTemplate::Timestamp {
                    min: bound(b.get("min"), &p, "min")?,
                    max: bound(b.get("max"), &p, "max")?,
                    granularity: bound(b.get("granularity"), &p, "granularity")?,
                }
            }
            "date" => {
                let b = body(b, &p, name)?;
                RtTemplate::Date {
                    min: bound(b.get("min"), &p, "min")?,
                    max: bound(b.get("max"), &p, "max")?,
                    granularity: opt_bound(b.get("granularity")),
                }
            }
            "bytes" => {
                let b = body(b, &p, name)?;
                RtTemplate::Bytes {
                    max_len: bound(b.get("max_len"), &p, "max_len")?,
                }
            }
            "list" => {
                let b = body(b, &p, name)?;
                let of = b.get("of").ok_or_else(|| {
                    TypeError::new(&format!("{p}/of"), E_UNBOUNDED, "`list` needs `of`")
                })?;
                RtTemplate::List {
                    max: bound(b.get("max"), &p, "max")?,
                    of: Box::new(Self::parse_at(of, &format!("{p}/of"))?),
                }
            }
            "table" => {
                let b = body(b, &p, name)?;
                let of = b.get("of").ok_or_else(|| {
                    TypeError::new(&format!("{p}/of"), E_UNBOUNDED, "`table` needs `of`")
                })?;
                let of_t = Self::parse_at(of, &format!("{p}/of"))?;
                if !matches!(of_t, RtTemplate::Struct { .. }) {
                    return Err(TypeError::new(
                        &format!("{p}/of"),
                        E_BAD_BOUND,
                        "`table` rows must be a `struct`",
                    ));
                }
                RtTemplate::Table {
                    max_rows: bound(b.get("max_rows"), &p, "max_rows")?,
                    of: Box::new(of_t),
                }
            }
            "struct" => {
                let b = body(b, &p, name)?;
                let mut fields = Vec::with_capacity(b.len());
                for (k, t) in b {
                    if k.is_empty() || k.len() > 128 {
                        return Err(TypeError::new(
                            &p,
                            E_BAD_BOUND,
                            "struct field names must be 1..=128 bytes",
                        ));
                    }
                    fields.push((
                        k.clone(),
                        Self::parse_at(t, &format!("{p}/{}", escape_ptr(k)))?,
                    ));
                }
                RtTemplate::Struct { fields }
            }
            "optional" => RtTemplate::Optional(Box::new(Self::parse_at(b, &p)?)),
            other => {
                return Err(TypeError::new(
                    path,
                    E_UNKNOWN_TYPE,
                    format!("unknown type `{other}`"),
                ))
            }
        })
    }

    /// Canonical wire form.
    pub fn to_json(&self) -> Value {
        fn b(x: &Bound) -> Value {
            match x {
                Bound::Lit(v) => v.clone(),
                Bound::Param(p) => Value::String(format!("${p}")),
            }
        }
        match self {
            RtTemplate::Bool => json!("bool"),
            RtTemplate::Int { min, max } => json!({"int": {"min": b(min), "max": b(max)}}),
            RtTemplate::Float {
                min,
                max,
                precision,
            } => {
                let mut o = json!({"min": b(min), "max": b(max)});
                if let Some(p) = precision {
                    o["precision"] = b(p);
                }
                json!({ "float": o })
            }
            RtTemplate::Decimal { scale, min, max } => {
                json!({"decimal": {"scale": scale, "min": b(min), "max": b(max)}})
            }
            RtTemplate::Enum { values } => json!({ "enum": values }),
            RtTemplate::String {
                max_len,
                charset,
                pattern,
            } => {
                let mut o = json!({"max_len": b(max_len)});
                if *charset != Charset::Unicode {
                    o["charset"] = json!(charset.name());
                }
                if let Some(p) = pattern {
                    o["pattern"] = json!(p);
                }
                json!({ "string": o })
            }
            RtTemplate::Timestamp {
                min,
                max,
                granularity,
            } => {
                json!({"timestamp": {"min": b(min), "max": b(max), "granularity": b(granularity)}})
            }
            RtTemplate::Date {
                min,
                max,
                granularity,
            } => {
                let mut o = json!({"min": b(min), "max": b(max)});
                if let Some(g) = granularity {
                    o["granularity"] = b(g);
                }
                json!({ "date": o })
            }
            RtTemplate::Bytes { max_len } => json!({"bytes": {"max_len": b(max_len)}}),
            RtTemplate::List { max, of } => json!({"list": {"max": b(max), "of": of.to_json()}}),
            RtTemplate::Table { max_rows, of } => {
                json!({"table": {"max_rows": b(max_rows), "of": of.to_json()}})
            }
            RtTemplate::Struct { fields } => {
                let mut m = Map::new();
                for (k, t) in fields {
                    m.insert(k.clone(), t.to_json());
                }
                json!({ "struct": m })
            }
            RtTemplate::Optional(t) => json!({ "optional": t.to_json() }),
        }
    }

    /// Names of params referenced by bounds.
    pub fn params(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.walk_bounds(&mut |b| {
            if let Bound::Param(p) = b {
                if !out.contains(p) {
                    out.push(p.clone());
                }
            }
        });
        out
    }

    fn walk_bounds(&self, f: &mut dyn FnMut(&Bound)) {
        match self {
            RtTemplate::Bool | RtTemplate::Enum { .. } => {}
            RtTemplate::Int { min, max } | RtTemplate::Decimal { min, max, .. } => {
                f(min);
                f(max)
            }
            RtTemplate::Float {
                min,
                max,
                precision,
            } => {
                f(min);
                f(max);
                if let Some(p) = precision {
                    f(p)
                }
            }
            RtTemplate::String { max_len, .. } | RtTemplate::Bytes { max_len } => f(max_len),
            RtTemplate::Timestamp {
                min,
                max,
                granularity,
            } => {
                f(min);
                f(max);
                f(granularity)
            }
            RtTemplate::Date {
                min,
                max,
                granularity,
            } => {
                f(min);
                f(max);
                if let Some(g) = granularity {
                    f(g)
                }
            }
            RtTemplate::List { max, of } => {
                f(max);
                of.walk_bounds(f)
            }
            RtTemplate::Table { max_rows, of } => {
                f(max_rows);
                of.walk_bounds(f)
            }
            RtTemplate::Struct { fields } => fields.iter().for_each(|(_, t)| t.walk_bounds(f)),
            RtTemplate::Optional(t) => t.walk_bounds(f),
        }
    }

    /// Resolve param references against `params` and check all bounds.
    pub fn bind(&self, params: &Map<String, Value>) -> Result<Rt, TypeError> {
        self.bind_at(params, "")
    }

    fn bind_at(&self, params: &Map<String, Value>, path: &str) -> Result<Rt, TypeError> {
        let resolve = |b: &Bound, field: &str| -> Result<Value, TypeError> {
            match b {
                Bound::Lit(v) => Ok(v.clone()),
                Bound::Param(p) => params.get(p).cloned().ok_or_else(|| {
                    TypeError::new(
                        &format!("{path}/{field}"),
                        E_UNRESOLVED,
                        format!("bound references param `${p}`, which is not provided"),
                    )
                }),
            }
        };
        let int = |b: &Bound, field: &str| -> Result<i64, TypeError> {
            let v = resolve(b, field)?;
            v.as_i64().ok_or_else(|| {
                TypeError::new(
                    &format!("{path}/{field}"),
                    E_BAD_BOUND,
                    format!("`{field}` must be an integer"),
                )
            })
        };
        let num = |b: &Bound, field: &str| -> Result<f64, TypeError> {
            let v = resolve(b, field)?;
            v.as_f64().filter(|x| x.is_finite()).ok_or_else(|| {
                TypeError::new(
                    &format!("{path}/{field}"),
                    E_BAD_BOUND,
                    format!("`{field}` must be a finite number"),
                )
            })
        };
        let len = |b: &Bound, field: &str, cap: u64| -> Result<u32, TypeError> {
            let v = resolve(b, field)?;
            let n = v.as_u64().ok_or_else(|| {
                TypeError::new(
                    &format!("{path}/{field}"),
                    E_BAD_BOUND,
                    format!("`{field}` must be a non-negative integer"),
                )
            })?;
            if n > cap {
                return Err(TypeError::new(
                    &format!("{path}/{field}"),
                    E_TOO_LARGE,
                    format!("`{field}` exceeds {cap}"),
                ));
            }
            Ok(n as u32)
        };
        let ts = |b: &Bound, field: &str| -> Result<i64, TypeError> {
            let v = resolve(b, field)?;
            match &v {
                Value::String(s) => parse_timestamp_ms(s),
                Value::Number(n) => n.as_i64(),
                _ => None,
            }
            // The ECMAScript time range: keeps `max - min` far from i64 overflow
            // (an overflowing range would compute as zero capacity).
            .filter(|t| t.unsigned_abs() <= MAX_TIME_MS)
            .ok_or_else(|| {
                TypeError::new(
                    &format!("{path}/{field}"),
                    E_BAD_BOUND,
                    format!("`{field}` must be an RFC 3339 timestamp or epoch ms"),
                )
            })
        };
        let dur = |b: &Bound, field: &str| -> Result<i64, TypeError> {
            let v = resolve(b, field)?;
            match &v {
                Value::String(s) => parse_duration_ms(s),
                Value::Number(n) => n.as_i64(),
                _ => None,
            }
            .filter(|g| *g > 0 && g.unsigned_abs() <= MAX_TIME_MS)
            .ok_or_else(|| {
                TypeError::new(
                    &format!("{path}/{field}"),
                    E_GRANULARITY,
                    format!("`{field}` must be a positive duration like \"15m\""),
                )
            })
        };
        let check_range = |lo: f64, hi: f64| -> Result<(), TypeError> {
            if lo > hi {
                Err(TypeError::new(
                    path,
                    E_EMPTY_RANGE,
                    format!("empty range: min {lo} > max {hi}"),
                ))
            } else {
                Ok(())
            }
        };
        Ok(match self {
            RtTemplate::Bool => Rt::Bool,
            RtTemplate::Int { min, max } => {
                let (lo, hi) = (int(min, "min")?, int(max, "max")?);
                check_range(lo as f64, hi as f64)?;
                Rt::Int { min: lo, max: hi }
            }
            RtTemplate::Float {
                min,
                max,
                precision,
            } => {
                let (lo, hi) = (num(min, "min")?, num(max, "max")?);
                check_range(lo, hi)?;
                let precision = match precision {
                    Some(p) => {
                        let p = num(p, "precision")?;
                        if p <= 0.0 {
                            return Err(TypeError::new(
                                &format!("{path}/precision"),
                                E_BAD_BOUND,
                                "`precision` must be > 0",
                            ));
                        }
                        Some(p)
                    }
                    None => None,
                };
                Rt::Float {
                    min: lo,
                    max: hi,
                    precision,
                }
            }
            RtTemplate::Decimal { scale, min, max } => {
                let (lo, hi) = (num(min, "min")?, num(max, "max")?);
                check_range(lo, hi)?;
                Rt::Decimal {
                    scale: *scale,
                    min: lo,
                    max: hi,
                }
            }
            RtTemplate::Enum { values } => Rt::Enum {
                values: values.clone(),
            },
            RtTemplate::String {
                max_len,
                charset,
                pattern,
            } => Rt::String {
                max_len: len(max_len, "max_len", MAX_LEN)?,
                charset: *charset,
                pattern: pattern.clone(),
            },
            RtTemplate::Timestamp {
                min,
                max,
                granularity,
            } => {
                let (lo, hi) = (ts(min, "min")?, ts(max, "max")?);
                check_range(lo as f64, hi as f64)?;
                Rt::Timestamp {
                    min: lo,
                    max: hi,
                    granularity_ms: dur(granularity, "granularity")?,
                }
            }
            RtTemplate::Date {
                min,
                max,
                granularity,
            } => {
                let d = |b: &Bound, field: &str| -> Result<i32, TypeError> {
                    let v = resolve(b, field)?;
                    v.as_str().and_then(parse_date_days).ok_or_else(|| {
                        TypeError::new(
                            &format!("{path}/{field}"),
                            E_BAD_BOUND,
                            format!("`{field}` must be YYYY-MM-DD"),
                        )
                    })
                };
                let (lo, hi) = (d(min, "min")?, d(max, "max")?);
                check_range(lo as f64, hi as f64)?;
                let g = match granularity {
                    None => 1,
                    Some(g) => {
                        let ms = dur(g, "granularity")?;
                        if ms % 86_400_000 != 0 {
                            return Err(TypeError::new(
                                &format!("{path}/granularity"),
                                E_GRANULARITY,
                                "date granularity must be whole days",
                            ));
                        }
                        i32::try_from(ms / 86_400_000).map_err(|_| {
                            TypeError::new(
                                &format!("{path}/granularity"),
                                E_GRANULARITY,
                                "granularity is too large",
                            )
                        })?
                    }
                };
                Rt::Date {
                    min: lo,
                    max: hi,
                    granularity_days: g,
                }
            }
            RtTemplate::Bytes { max_len } => Rt::Bytes {
                max_len: len(max_len, "max_len", MAX_LEN)?,
            },
            RtTemplate::List { max, of } => Rt::List {
                max: len(max, "max", MAX_LIST)?,
                of: Box::new(of.bind_at(params, &format!("{path}/list/of"))?),
            },
            RtTemplate::Table { max_rows, of } => Rt::Table {
                max_rows: len(max_rows, "max_rows", MAX_LIST)?,
                of: Box::new(of.bind_at(params, &format!("{path}/table/of"))?),
            },
            RtTemplate::Struct { fields } => {
                let mut out = Vec::with_capacity(fields.len());
                for (k, t) in fields {
                    out.push((
                        k.clone(),
                        t.bind_at(params, &format!("{path}/struct/{}", escape_ptr(k)))?,
                    ));
                }
                Rt::Struct { fields: out }
            }
            RtTemplate::Optional(t) => {
                Rt::Optional(Box::new(t.bind_at(params, &format!("{path}/optional"))?))
            }
        })
    }
}

impl Rt {
    /// Parse a concrete type (no param references allowed).
    pub fn from_json(v: &Value) -> Result<Rt, TypeError> {
        RtTemplate::from_json(v)?.bind(&Map::new())
    }

    /// Concrete wire form (bounds are literals).
    pub fn to_json(&self) -> Value {
        match self {
            Rt::Bool => json!("bool"),
            Rt::Int { min, max } => json!({"int": {"min": min, "max": max}}),
            Rt::Float {
                min,
                max,
                precision,
            } => {
                let mut o = json!({"min": min, "max": max});
                if let Some(p) = precision {
                    o["precision"] = json!(p);
                }
                json!({ "float": o })
            }
            Rt::Decimal { scale, min, max } => {
                json!({"decimal": {"scale": scale, "min": min, "max": max}})
            }
            Rt::Enum { values } => json!({ "enum": values }),
            Rt::String {
                max_len,
                charset,
                pattern,
            } => {
                let mut o = json!({"max_len": max_len});
                if *charset != Charset::Unicode {
                    o["charset"] = json!(charset.name());
                }
                if let Some(p) = pattern {
                    o["pattern"] = json!(p);
                }
                json!({ "string": o })
            }
            Rt::Timestamp {
                min,
                max,
                granularity_ms,
            } => json!({"timestamp": {
                "min": format_timestamp_ms(*min), "max": format_timestamp_ms(*max),
                "granularity": crate::format_duration_ms(*granularity_ms)}}),
            Rt::Date {
                min,
                max,
                granularity_days,
            } => json!({"date": {
                "min": format_date_days(*min), "max": format_date_days(*max),
                "granularity": format!("{granularity_days}d")}}),
            Rt::Bytes { max_len } => json!({"bytes": {"max_len": max_len}}),
            Rt::List { max, of } => json!({"list": {"max": max, "of": of.to_json()}}),
            Rt::Table { max_rows, of } => {
                json!({"table": {"max_rows": max_rows, "of": of.to_json()}})
            }
            Rt::Struct { fields } => {
                let mut m = Map::new();
                for (k, t) in fields {
                    m.insert(k.clone(), t.to_json());
                }
                json!({ "struct": m })
            }
            Rt::Optional(t) => json!({ "optional": t.to_json() }),
        }
    }
}

pub(crate) fn escape_ptr(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

/// Parse RFC 3339 (or a bare date) into epoch ms.
pub fn parse_timestamp_ms(s: &str) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc().timestamp_millis());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(dt.and_utc().timestamp_millis());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    None
}

/// Format epoch ms as canonical RFC 3339 UTC (`Z`, millisecond precision only when needed).
pub fn format_timestamp_ms(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(dt) => {
            if ms % 1000 == 0 {
                dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            } else {
                dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
            }
        }
        None => ms.to_string(),
    }
}

pub fn parse_date_days(s: &str) -> Option<i32> {
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1)?;
    Some((d - epoch).num_days() as i32)
}

pub fn format_date_days(days: i32) -> String {
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    match epoch.checked_add_signed(chrono::Duration::days(days as i64)) {
        Some(d) => d.format("%Y-%m-%d").to_string(),
        None => days.to_string(),
    }
}
