//! The Holder's verifier, minus private policy, compiled to Wasm (and usable
//! natively). Every function takes and returns JSON strings so SDKs in any
//! language can bind it with no shared types.

use remit_types::RtTemplate;
use serde_json::{json, Map, Value};
use wasm_bindgen::prelude::*;

fn parse(s: &str) -> Result<Value, String> {
    serde_json::from_str(s).map_err(|e| format!("invalid JSON: {e}"))
}

fn returns_template(v: &Value) -> Result<RtTemplate, remit_types::TypeError> {
    let is_schema = v.as_object().is_some_and(|o| {
        o.contains_key("$schema") || o.contains_key("type") || o.contains_key("anyOf")
    });
    if is_schema {
        RtTemplate::from_json_schema(v)
    } else {
        RtTemplate::from_json(v)
    }
}

/// RFC 8785 canonical JSON.
#[wasm_bindgen]
pub fn canonicalize(json: &str) -> Result<String, String> {
    remit_wire::jcs::canonicalize(&parse(json)?).map_err(|e| e.to_string())
}

/// `remit_id` and `params_sha256` of a manifest.
#[wasm_bindgen]
pub fn remit_id(manifest: &str) -> Result<String, String> {
    let m = remit_wire::Manifest::from_value(parse(manifest)?).map_err(|e| e.to_string())?;
    Ok(json!({"remit_id": m.remit_id(), "params_sha256": m.params_sha256()}).to_string())
}

/// Capacity of a `returns` type bound with `params`:
/// `{ok, bits, bits_ceil, result_bits, type, ts, params, error?}`.
#[wasm_bindgen]
pub fn capacity(returns: &str, params: &str) -> String {
    let r = (|| -> Result<Value, Value> {
        let t = returns_template(&parse(returns).map_err(|e| json!({"code": "RMT-E0002", "message": e}))?)
            .map_err(|e| json!({"code": e.code(), "path": format!("/returns{}", e.path()), "message": e.message()}))?;
        let p: Map<String, Value> =
            match parse(params).map_err(|e| json!({"code": "RMT-E0002", "message": e}))? {
                Value::Object(o) => o,
                _ => Map::new(),
            };
        let rt = t.bind(&p).map_err(|e| json!({"code": e.code(), "path": format!("/returns{}", e.path()), "message": e.message()}))?;
        let bits = rt.capacity_bits_ceil();
        if bits == u64::MAX {
            return Err(
                json!({"code": "RMT-E0130", "path": "/returns", "message": "result type capacity is unbounded"}),
            );
        }
        Ok(json!({
            "ok": true,
            "bits": rt.capacity_bits(),
            "bits_ceil": rt.capacity_bits_ceil(),
            "result_bits": bits.saturating_add(remit_types::status_bits() as u64),
            "type": rt.to_string(),
            "ts": rt.to_ts(),
            "params": t.params(),
            "json_schema": t.to_json_schema(),
        }))
    })();
    match r {
        Ok(v) => v.to_string(),
        Err(e) => json!({"ok": false, "error": e}).to_string(),
    }
}

/// Validate (and normalize) a value against a bound type.
#[wasm_bindgen]
pub fn validate(returns: &str, params: &str, value: &str) -> String {
    let r = (|| -> Result<Value, String> {
        let p: Map<String, Value> = parse(params)?.as_object().cloned().unwrap_or_default();
        let rt = returns_template(&parse(returns)?)
            .map_err(|e| e.to_string())?
            .bind(&p)
            .map_err(|e| e.to_string())?;
        rt.validate(&parse(value)?).map_err(|v| v.to_string())
    })();
    match r {
        Ok(v) => json!({"ok": true, "value": v}).to_string(),
        Err(e) => json!({"ok": false, "error": e}).to_string(),
    }
}

/// Check SQL against the Remit SQL profile.
#[wasm_bindgen]
pub fn check_sql(sql: &str) -> String {
    match remit_sql::check(sql, &remit_sql::Profile::default()) {
        Ok(f) => json!({"ok": true, "facts": f}).to_string(),
        Err(e) => json!({"ok": false, "error": e}).to_string(),
    }
}

/// Bind SQL against a catalog document: output columns, lineage, diagnostics.
#[wasm_bindgen]
pub fn bind_sql(sql: &str, catalog: &str) -> String {
    let cat = match parse(catalog) {
        Ok(c) => c,
        Err(e) => {
            return json!({"ok": false, "error": {"code": "RMT-E0002", "message": e}}).to_string()
        }
    };
    let mut profile = remit_sql::Profile::default();
    if cat["indexes"].as_array().is_some_and(|a| !a.is_empty()) {
        profile
            .table_functions
            .extend(["fts".to_string(), "knn".to_string()]);
    }
    match remit_sql::bind::bind(sql, &cat, &profile) {
        Ok(b) => json!({"ok": true, "bound": b}).to_string(),
        Err(e) => json!({"ok": false, "error": e}).to_string(),
    }
}

/// Convert a JSON Schema (Zod / Valibot / ArkType `toJSONSchema`) to RT JSON.
#[wasm_bindgen]
pub fn rt_from_json_schema(schema: &str) -> String {
    match parse(schema).and_then(|s| RtTemplate::from_json_schema(&s).map_err(|e| e.to_string())) {
        Ok(t) => json!({"ok": true, "rt": t.to_json()}).to_string(),
        Err(e) => json!({"ok": false, "error": e}).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exports() {
        let c: Value =
            serde_json::from_str(&capacity(r#"{"list":{"max":3,"of":"bool"}}"#, "{}")).unwrap();
        assert_eq!(c["bits_ceil"], json!(5));
        assert_eq!(
            canonicalize(r#"{"b":1,"a":2}"#).unwrap(),
            r#"{"a":2,"b":1}"#
        );
        let s: Value = serde_json::from_str(&check_sql("SELECT now()")).unwrap();
        assert_eq!(s["ok"], json!(false));
        let v: Value =
            serde_json::from_str(&validate(r#"{"int":{"min":0,"max":3}}"#, "{}", "5")).unwrap();
        assert_eq!(v["ok"], json!(false));
    }
    #[test]
    fn excessive_capacity_is_rejected() {
        let mut rt = json!("bool");
        for _ in 0..3 {
            rt = json!({"list": {"max": 16777216, "of": rt}});
        }
        let result: Value = serde_json::from_str(&capacity(&rt.to_string(), "{}")).unwrap();
        assert_eq!(result["ok"], false);
        assert!(result.get("result_bits").is_none());
    }
}
