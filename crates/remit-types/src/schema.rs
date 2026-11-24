//! Interop: canonical JSON Schema 2020-12 profile (`x-remit-*` bounds) and
//! TypeScript type rendering for codegen.

use serde_json::{json, Map, Value};

use crate::parse::{E_BAD_BOUND, E_UNBOUNDED, E_UNKNOWN_TYPE};
use crate::{Bound, Charset, Rt, RtTemplate, TypeError};

fn b(x: &Bound) -> Value {
    match x {
        Bound::Lit(v) => v.clone(),
        Bound::Param(p) => Value::String(format!("${p}")),
    }
}

impl RtTemplate {
    /// Render as JSON Schema 2020-12 with `x-remit-*` bounds.
    pub fn to_json_schema(&self) -> Value {
        let mut s = self.schema_inner();
        if let Value::Object(o) = &mut s {
            o.insert(
                "$schema".into(),
                json!("https://json-schema.org/draft/2020-12/schema"),
            );
        }
        s
    }

    fn schema_inner(&self) -> Value {
        match self {
            RtTemplate::Bool => json!({"type": "boolean"}),
            RtTemplate::Int { min, max } => {
                json!({"type": "integer", "minimum": b(min), "maximum": b(max)})
            }
            RtTemplate::Float {
                min,
                max,
                precision,
            } => {
                let mut o = json!({"type": "number", "minimum": b(min), "maximum": b(max)});
                if let Some(p) = precision {
                    o["x-remit-precision"] = b(p);
                }
                o
            }
            RtTemplate::Decimal { scale, min, max } => json!({
                "type": "string", "format": "decimal", "x-remit-scale": scale,
                "x-remit-minimum": b(min), "x-remit-maximum": b(max)}),
            RtTemplate::Enum { values } => json!({"type": "string", "enum": values}),
            RtTemplate::String {
                max_len,
                charset,
                pattern,
            } => {
                let mut o = json!({"type": "string", "maxLength": b(max_len)});
                if *charset != Charset::Unicode {
                    o["x-remit-charset"] = json!(charset.name());
                }
                if let Some(p) = pattern {
                    o["pattern"] = json!(p);
                }
                o
            }
            RtTemplate::Timestamp {
                min,
                max,
                granularity,
            } => json!({
                "type": "string", "format": "date-time",
                "x-remit-minimum": b(min), "x-remit-maximum": b(max), "x-remit-granularity": b(granularity)}),
            RtTemplate::Date {
                min,
                max,
                granularity,
            } => {
                let mut o = json!({"type": "string", "format": "date", "x-remit-minimum": b(min), "x-remit-maximum": b(max)});
                if let Some(g) = granularity {
                    o["x-remit-granularity"] = b(g);
                }
                o
            }
            RtTemplate::Bytes { max_len } => {
                json!({"type": "string", "contentEncoding": "base64", "x-remit-maxBytes": b(max_len)})
            }
            RtTemplate::List { max, of } => {
                json!({"type": "array", "maxItems": b(max), "items": of.schema_inner()})
            }
            RtTemplate::Table { max_rows, of } => {
                json!({"type": "array", "maxItems": b(max_rows), "items": of.schema_inner(), "x-remit-table": true})
            }
            RtTemplate::Struct { fields } => {
                let mut props = Map::new();
                let mut req = Vec::new();
                for (k, t) in fields {
                    props.insert(k.clone(), t.schema_inner());
                    if !matches!(t, RtTemplate::Optional(_)) {
                        req.push(Value::String(k.clone()));
                    }
                }
                json!({"type": "object", "properties": props, "required": req, "additionalProperties": false})
            }
            RtTemplate::Optional(t) => json!({"anyOf": [t.schema_inner(), {"type": "null"}]}),
        }
    }

    /// Accept a JSON Schema (as produced by Zod 4 / Valibot / ArkType
    /// `toJSONSchema`, or by [`to_json_schema`]) and convert it to RT.
    /// Unbounded schemas are rejected with the same codes as RT.
    pub fn from_json_schema(s: &Value) -> Result<Self, TypeError> {
        from_schema(s, "")
    }
}

fn from_schema(s: &Value, path: &str) -> Result<RtTemplate, TypeError> {
    let o = s
        .as_object()
        .ok_or_else(|| TypeError::new(path, E_UNKNOWN_TYPE, "schema must be an object"))?;
    let get = |k: &str| o.get(k);
    let bound_of = |keys: &[&str], field: &str| -> Result<Bound, TypeError> {
        for k in keys {
            if let Some(v) = o.get(*k) {
                return Ok(match v {
                    Value::String(s) if s.starts_with('$') => Bound::Param(s[1..].into()),
                    v => Bound::Lit(v.clone()),
                });
            }
        }
        Err(TypeError::new(
            path,
            E_UNBOUNDED,
            format!("schema is unbounded: add `{field}`"),
        ))
    };
    // Nullable forms.
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(alts)) = get(key) {
            let non_null: Vec<&Value> = alts
                .iter()
                .filter(|a| a.get("type") != Some(&json!("null")))
                .collect();
            if non_null.len() == 1 && alts.len() == 2 {
                return Ok(RtTemplate::Optional(Box::new(from_schema(
                    non_null[0],
                    path,
                )?)));
            }
            return Err(TypeError::new(
                path,
                E_UNKNOWN_TYPE,
                format!("`{key}` is only supported as T | null"),
            ));
        }
    }
    if let Some(Value::Array(e)) = get("enum") {
        let values: Option<Vec<String>> = e.iter().map(|x| x.as_str().map(String::from)).collect();
        return Ok(RtTemplate::Enum {
            values: values.ok_or_else(|| {
                TypeError::new(path, E_BAD_BOUND, "only string enums are supported")
            })?,
        });
    }
    if let Some(c) = get("const").and_then(Value::as_str) {
        return Ok(RtTemplate::Enum {
            values: vec![c.to_string()],
        });
    }
    let ty = match get("type") {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Array(ts)) => {
            let non_null: Vec<&Value> = ts.iter().filter(|t| *t != "null").collect();
            if non_null.len() == 1 && ts.len() == 2 {
                let mut inner = o.clone();
                inner.insert("type".into(), non_null[0].clone());
                return Ok(RtTemplate::Optional(Box::new(from_schema(
                    &Value::Object(inner),
                    path,
                )?)));
            }
            return Err(TypeError::new(
                path,
                E_UNKNOWN_TYPE,
                "union types are only supported as [T, \"null\"]",
            ));
        }
        _ => {
            return Err(TypeError::new(
                path,
                E_UNKNOWN_TYPE,
                "schema needs a `type`",
            ))
        }
    };
    Ok(match ty.as_str() {
        "boolean" => RtTemplate::Bool,
        "integer" => RtTemplate::Int {
            min: bound_of(&["minimum", "x-remit-minimum"], "minimum")?,
            max: bound_of(&["maximum", "x-remit-maximum"], "maximum")?,
        },
        "number" => RtTemplate::Float {
            min: bound_of(&["minimum", "x-remit-minimum"], "minimum")?,
            max: bound_of(&["maximum", "x-remit-maximum"], "maximum")?,
            precision: o
                .get("x-remit-precision")
                .or_else(|| o.get("multipleOf"))
                .map(|v| match v {
                    Value::String(s) if s.starts_with('$') => Bound::Param(s[1..].into()),
                    v => Bound::Lit(v.clone()),
                }),
        },
        "string" => match get("format").and_then(Value::as_str) {
            Some("date-time") => RtTemplate::Timestamp {
                min: bound_of(&["x-remit-minimum", "formatMinimum"], "x-remit-minimum")?,
                max: bound_of(&["x-remit-maximum", "formatMaximum"], "x-remit-maximum")?,
                granularity: bound_of(&["x-remit-granularity"], "x-remit-granularity")?,
            },
            Some("date") => RtTemplate::Date {
                min: bound_of(&["x-remit-minimum", "formatMinimum"], "x-remit-minimum")?,
                max: bound_of(&["x-remit-maximum", "formatMaximum"], "x-remit-maximum")?,
                granularity: o.get("x-remit-granularity").map(|v| Bound::Lit(v.clone())),
            },
            Some("decimal") => RtTemplate::Decimal {
                scale: o.get("x-remit-scale").and_then(Value::as_u64).unwrap_or(2) as u32,
                min: bound_of(&["x-remit-minimum"], "x-remit-minimum")?,
                max: bound_of(&["x-remit-maximum"], "x-remit-maximum")?,
            },
            _ if o.get("contentEncoding").and_then(Value::as_str) == Some("base64") => {
                RtTemplate::Bytes {
                    max_len: bound_of(&["x-remit-maxBytes"], "x-remit-maxBytes")?,
                }
            }
            _ => RtTemplate::String {
                max_len: bound_of(&["maxLength"], "maxLength")?,
                charset: o
                    .get("x-remit-charset")
                    .and_then(Value::as_str)
                    .and_then(Charset::from_name)
                    .unwrap_or(Charset::Unicode),
                pattern: o
                    .get("pattern")
                    .and_then(Value::as_str)
                    .map(|p| p.trim_start_matches('^').trim_end_matches('$').to_string()),
            },
        },
        "array" => {
            let items = get("items")
                .ok_or_else(|| TypeError::new(path, E_UNBOUNDED, "array schema needs `items`"))?;
            let of = Box::new(from_schema(items, &format!("{path}/items"))?);
            let max = bound_of(&["maxItems"], "maxItems")?;
            if o.get("x-remit-table") == Some(&Value::Bool(true)) {
                RtTemplate::Table { max_rows: max, of }
            } else {
                RtTemplate::List { max, of }
            }
        }
        "object" => {
            let props = get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let req: Vec<&str> = get("required")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut fields = Vec::new();
            for (k, ps) in &props {
                let t = from_schema(ps, &format!("{path}/properties/{k}"))?;
                let t = if req.contains(&k.as_str()) || matches!(t, RtTemplate::Optional(_)) {
                    t
                } else {
                    RtTemplate::Optional(Box::new(t))
                };
                fields.push((k.clone(), t));
            }
            RtTemplate::Struct { fields }
        }
        other => {
            return Err(TypeError::new(
                path,
                E_UNKNOWN_TYPE,
                format!("unsupported schema type `{other}`"),
            ))
        }
    })
}

impl Rt {
    /// Render as a TypeScript type expression (for generated `.d.ts`).
    pub fn to_ts(&self) -> String {
        match self {
            Rt::Bool => "boolean".into(),
            Rt::Int { .. } | Rt::Float { .. } => "number".into(),
            Rt::Decimal { .. } => "string".into(),
            Rt::Enum { values } => values
                .iter()
                .map(|v| serde_json::to_string(v).unwrap())
                .collect::<Vec<_>>()
                .join(" | "),
            Rt::String { .. } | Rt::Bytes { .. } => "string".into(),
            Rt::Timestamp { .. } | Rt::Date { .. } => "Date".into(),
            Rt::List { of, .. } | Rt::Table { of, .. } => format!("Array<{}>", of.to_ts()),
            Rt::Struct { fields } => {
                let parts: Vec<String> = fields
                    .iter()
                    .map(|(k, t)| match t {
                        Rt::Optional(inner) => format!("{}?: {} | null", ts_key(k), inner.to_ts()),
                        t => format!("{}: {}", ts_key(k), t.to_ts()),
                    })
                    .collect();
                format!("{{ {} }}", parts.join("; "))
            }
            Rt::Optional(t) => format!("{} | null", t.to_ts()),
        }
    }
}

fn ts_key(k: &str) -> String {
    if k.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && !k.starts_with(|c: char| c.is_ascii_digit())
    {
        k.to_string()
    } else {
        serde_json::to_string(k).unwrap()
    }
}
