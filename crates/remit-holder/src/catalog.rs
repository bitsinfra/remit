//! `GET /.well-known/remit`: the signed, content-addressed, per-principal
//! scoped catalog (resources, policy hints, runtime, examples, stats).

use std::collections::BTreeSet;

use datafusion::arrow::array::{Array, AsArray};
use datafusion::arrow::datatypes::DataType;
use remit_read::{arrowconv::kind_of, Principal};
use serde_json::{json, Value};

use crate::state::{Holder, Isolation};

pub fn build(h: &Holder, groups: &[String]) -> Value {
    let p = Principal {
        id: String::new(),
        groups: groups.to_vec(),
    };
    let plane = h.plane();
    let mut resources = Vec::new();
    let mut hints = Vec::new();
    let visible = plane.visible_tables(&p);
    for name in &visible {
        let Some(schema) = plane.exposed_schema(name) else {
            continue;
        };
        let r = h.resources.get(name).cloned().unwrap_or_default();
        let cols: Vec<Value> = schema
            .fields()
            .iter()
            .map(|f| {
                let c = r.column(f.name());
                let mut o = json!({"name": f.name(), "type": kind_of(f.data_type()), "nullable": f.is_nullable()});
                if let Some(d) = &c.description {
                    o["description"] = json!(d);
                }
                if c.mask.is_some() {
                    o["masked"] = json!(c.mask);
                }
                if c.publish_enum {
                    o["enum"] = json!(distinct_values(&plane, name, f.name()));
                }
                if let Some(b) = c.bounds {
                    o["bounds"] = json!(b);
                }
                o
            })
            .collect();
        let rows = plane.row_count(name).unwrap_or(0);
        let mut hint = json!({
            "operations": r.operations(),
            "aggregate_only": r.aggregate_only,
        });
        if let Some(b) = r.max_bits {
            hint["max_bits_per_remit"] = json!(b);
        }
        if !r.purposes.is_empty() {
            hint["purposes"] = json!(r.purposes);
        }
        if let Some(k) = r.k {
            hint["k"] = json!(k);
            if let Some(pu) = &r.privacy_unit {
                hint["privacy_unit"] = json!(pu);
            }
        }
        if let Some(dp) = &r.dp {
            hint["dp"] = json!({"epsilon_per_day": dp.epsilon_per_day, "max_epsilon_per_remit": dp.max_epsilon_per_remit, "delta": dp.delta,
                "mechanism": dp.mechanism, "max_contributions": dp.max_contributions, "privacy_unit": r.privacy_unit});
        }
        if let Some(a) = &r.approval {
            hint["approval"] = json!(a);
        }
        if r.owner_column.is_some() {
            hint["owner_rows_only"] = json!(true);
        }
        hints.push(hint_line(name, &cols, &r));
        resources.push(json!({
            "name": name,
            "kind": "table",
            "description": r.description,
            "columns": cols,
            "labels": r.labels,
            "sensitivity": r.sensitivity.clone().unwrap_or_else(|| "medium".into()),
            "rows": remit_analyze::bucket(rows),
            "hints": hint,
            "terms": {"retain_days": r.retain_days, "forward": r.forward.unwrap_or(!r.labels.iter().any(|l| l == "no-forward"))},
        }));
    }
    let hl = &h.cfg.runtime.limits;
    let (engine, wasm) = match &h.isolation {
        Isolation::None => (Value::Null, Value::Null),
        Isolation::Engines(m) => (
            json!(m.iter().map(|(lang, e)| json!({"lang": lang, "engine": if lang.starts_with("python") { "monty" } else { "boa" }, "sha256": e.sha256()})).collect::<Vec<_>>()),
            json!(remit_kernel::wasmtime_version()),
        ),
    };
    let mut modes: Vec<String> = hl.modes.clone();
    if matches!(h.isolation, Isolation::None) {
        modes.retain(|m| m != "kernel");
    }
    let vis: BTreeSet<&String> = visible.iter().collect();
    let stats: serde_json::Map<String, Value> = h
        .stats
        .read()
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| vis.contains(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "remit": remit_wire::REMIT_VERSION,
        "holder": h.id(),
        "keys": [{"kid": h.signer.key_id(), "did_key": h.signer.did_key(), "alg": h.signer.public_key().alg(), "jwk": h.signer.public_key().jwk()}],
        "resources": resources,
        "policy_hints": hints,
        "purposes": purposes(h, &vis),
        "runtime": {
            "modes": modes,
            "languages": if matches!(h.isolation, Isolation::None) { json!([]) } else { json!(hl.languages) },
            "limits": {
                "max_fuel": hl.max_fuel, "max_memory_bytes": hl.max_memory_bytes, "max_wall_ms": hl.max_wall_ms,
                "max_output_bytes": hl.max_output_bytes, "max_rows_per_read": hl.max_rows_per_read,
                "max_calls_per_read": hl.max_calls_per_read,
                "defaults": {"fuel": hl.default_fuel, "memory_bytes": hl.default_memory_bytes, "wall_ms": hl.default_wall_ms, "output_bytes": hl.default_output_bytes},
            },
            "fuel_prices": remit_kernel::FuelPrices::default(),
            "fuel_calibration": remit_kernel::FUEL_CALIBRATION,
            "functions": h.functions.visible(groups).iter().filter_map(|n| h.functions.get(n).map(|d| json!({"name": n, "description": d.description, "fuel": d.fuel}))).collect::<Vec<_>>(),
            "engine": engine,
            "wasmtime": wasm,
            "isolation": h.cfg.holder.isolation,
            "status_set": remit_types::STATUS_SET,
            "status_bits": remit_types::status_bits(),
        },
        "indexes": plane.indexes().filter(|i| vis.contains(&i.table)).map(|i| json!({
            "name": i.name, "kind": i.kind, "table": i.table, "id_column": i.id_column,
            "function": if i.kind == "fulltext" { "fts(index, query, k) -> (id, score)" } else { "knn(index, vector_json, k) -> (id, score)" },
        })).collect::<Vec<_>>(),
        "examples": h.examples.iter().filter(|e| example_visible(h, e, &vis)).collect::<Vec<_>>(),
        "stats": stats,
        "endpoints": {
            "check": "/remit/v1/check", "run": "/remit/v1/run", "runs": "/remit/v1/runs/{id}",
            "blobs": "/remit/v1/blobs/{sha256}", "receipts": "/remit/v1/receipts/{id}", "mcp": "/mcp", "a2a": "/a2a",
        },
    })
}

/// An example is shown only if every resource it reads is visible.
fn example_visible(h: &Holder, e: &Value, vis: &BTreeSet<&String>) -> bool {
    let profile = h.plane().sql_profile();
    e["manifest"]["reads"].as_object().is_some_and(|rs| {
        rs.values().all(|r| {
            remit_sql::check(r["sql"].as_str().unwrap_or(""), &profile).is_ok_and(|f| {
                f.tables.iter().all(|t| vis.contains(t))
                    && f.table_function_calls.iter().all(|(_, ix)| {
                        ix.as_deref()
                            .and_then(|i| h.plane().index(i).map(|c| vis.contains(&c.table)))
                            .unwrap_or(false)
                    })
            })
        })
    })
}

/// Purposes of *visible* resources only.
fn purposes(h: &Holder, vis: &BTreeSet<&String>) -> Vec<String> {
    let mut v: Vec<String> = h
        .resources
        .iter()
        .filter(|(n, _)| vis.contains(n))
        .flat_map(|(_, r)| r.purposes.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn hint_line(name: &str, cols: &[Value], r: &remit_read::ResourceConfig) -> String {
    let names: Vec<&str> = cols.iter().filter_map(|c| c["name"].as_str()).collect();
    let mut parts = vec![format!("`{name}`: columns {{{}}}", names.join(", "))];
    if r.aggregate_only {
        parts.push("aggregate-only".into());
    }
    if let Some(k) = r.k {
        parts.push(format!("k ≥ {k}"));
    }
    if let Some(dp) = &r.dp {
        parts.push(format!("DP ε ≤ {}/day", dp.epsilon_per_day));
    }
    if let Some(b) = r.max_bits {
        parts.push(format!("≤{b} bits/remit"));
    }
    if !r.purposes.is_empty() {
        parts.push(format!("purpose ∈ {{{}}}", r.purposes.join(", ")));
    }
    if r.owner_column.is_some() {
        parts.push("owner rows only".into());
    }
    parts.join("; ")
}

/// Distinct values of a published enum column (trusted read of the snapshot).
fn distinct_values(plane: &remit_read::ReadPlane, table: &str, col: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    if let Some(batches) = plane.raw_batches(table) {
        for b in batches.iter() {
            if let Ok(i) = b.schema().index_of(col) {
                let a = b.column(i);
                if matches!(a.data_type(), DataType::Utf8) {
                    let s = a.as_string::<i32>();
                    for r in 0..s.len() {
                        if !s.is_null(r) {
                            out.insert(s.value(r).to_string());
                        }
                    }
                }
            }
            if out.len() > 1024 {
                break;
            }
        }
    }
    out.into_iter().collect()
}
