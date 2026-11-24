//! `remit dev`: a local Holder emulator seeded with synthetic data generated
//! from a pulled catalog's schema and stats profiles. Admission mirrors the
//! catalog's public hints (aggregate-only, k, purposes, bit caps) but any
//! principal is allowed, and kernel error messages are returned (the data is
//! synthetic). Use it for shape, type and runtime-error checks, not results.

use std::path::Path;
use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, BooleanBuilder, Float64Builder, Int64Builder, StringBuilder,
    TimestampMillisecondBuilder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use rand::{Rng, SeedableRng};
use remit_read::ResourceConfig;
use serde_json::Value;

pub fn synthesize(
    c: &Value,
    rows: usize,
) -> Vec<(String, Arc<Schema>, RecordBatch, ResourceConfig)> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let now = chrono::Utc::now().timestamp_millis();
    let mut out = Vec::new();
    for r in c["resources"].as_array().into_iter().flatten() {
        let name = r["name"].as_str().unwrap_or("").to_string();
        let stats = &c["stats"][&name]["columns"];
        let mut fields = Vec::new();
        let mut arrays: Vec<ArrayRef> = Vec::new();
        for col in r["columns"].as_array().into_iter().flatten() {
            let cn = col["name"].as_str().unwrap_or("").to_string();
            let nullable = col["nullable"] != Value::Bool(false);
            let null = |rng: &mut rand::rngs::StdRng| nullable && rng.gen_bool(0.03);
            let st = &stats[&cn];
            match col["type"].as_str().unwrap_or("string") {
                "int" | "float" => {
                    let (lo, hi) = range_from_hist(st)
                        .or_else(|| {
                            col["bounds"].as_array().map(|b| {
                                (
                                    b[0].as_f64().unwrap_or(0.0),
                                    b[1].as_f64().unwrap_or(1000.0),
                                )
                            })
                        })
                        .unwrap_or((0.0, 1000.0));
                    if col["type"] == "int" {
                        let mut b = Int64Builder::new();
                        for _ in 0..rows {
                            if null(&mut rng) {
                                b.append_null()
                            } else {
                                b.append_value(rng.gen_range(lo as i64..=hi.max(lo + 1.0) as i64))
                            }
                        }
                        fields.push(Field::new(&cn, DataType::Int64, true));
                        arrays.push(Arc::new(b.finish()));
                    } else {
                        let mut b = Float64Builder::new();
                        for _ in 0..rows {
                            if null(&mut rng) {
                                b.append_null()
                            } else {
                                b.append_value(
                                    (rng.gen_range(lo..hi.max(lo + 1.0)) * 100.0).round() / 100.0,
                                )
                            }
                        }
                        fields.push(Field::new(&cn, DataType::Float64, true));
                        arrays.push(Arc::new(b.finish()));
                    }
                }
                "timestamp" | "date" => {
                    let (lo, hi) = (now - 30 * 86_400_000, now + 30 * 86_400_000);
                    let mut b = TimestampMillisecondBuilder::new().with_timezone("UTC");
                    for _ in 0..rows {
                        // Quarter-hour aligned, business-hours-ish.
                        let t = rng.gen_range(lo..hi);
                        let t = t - t.rem_euclid(900_000);
                        if null(&mut rng) {
                            b.append_null()
                        } else {
                            b.append_value(t)
                        }
                    }
                    fields.push(Field::new(
                        &cn,
                        DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                        true,
                    ));
                    arrays.push(Arc::new(b.finish()));
                }
                "bool" => {
                    let mut b = BooleanBuilder::new();
                    for _ in 0..rows {
                        if null(&mut rng) {
                            b.append_null()
                        } else {
                            b.append_value(rng.gen_bool(0.5))
                        }
                    }
                    fields.push(Field::new(&cn, DataType::Boolean, true));
                    arrays.push(Arc::new(b.finish()));
                }
                _ => {
                    let vals: Vec<String> = col["enum"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut b = StringBuilder::new();
                    for i in 0..rows {
                        if null(&mut rng) {
                            b.append_null();
                        } else if !vals.is_empty() {
                            b.append_value(&vals[rng.gen_range(0..vals.len())]);
                        } else {
                            b.append_value(format!("{cn}_{}", i % (rows / 3).max(1)));
                        }
                    }
                    fields.push(Field::new(&cn, DataType::Utf8, true));
                    arrays.push(Arc::new(b.finish()));
                }
            }
        }
        let schema = Arc::new(Schema::new(fields));
        let Ok(batch) = RecordBatch::try_new(schema.clone(), arrays) else {
            continue;
        };
        let h = &r["hints"];
        let rc = ResourceConfig {
            description: r["description"].as_str().map(String::from),
            labels: r["labels"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            aggregate_only: h["aggregate_only"] == Value::Bool(true),
            k: h["k"].as_u64(),
            privacy_unit: h["privacy_unit"].as_str().map(String::from),
            purposes: h["purposes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            max_bits: h["max_bits_per_remit"].as_u64(),
            ..Default::default()
        };
        out.push((name, schema, batch, rc));
    }
    out
}

fn range_from_hist(st: &Value) -> Option<(f64, f64)> {
    let h = st["histogram"].as_array()?;
    let lo = h
        .iter()
        .filter_map(|b| b["gte"].as_f64())
        .fold(f64::INFINITY, f64::min);
    let hi = h
        .iter()
        .filter_map(|b| b["lt"].as_f64())
        .fold(f64::NEG_INFINITY, f64::max);
    (lo.is_finite() && hi.is_finite() && hi > lo).then_some((lo, hi))
}

pub async fn run(catalog: &Path, listen: &str, engine: &Path, rows: usize) -> anyhow::Result<()> {
    let c: Value = serde_json::from_str(&std::fs::read_to_string(catalog)?)?;
    let id = format!(
        "did:web:dev.{}",
        c["holder"]
            .as_str()
            .unwrap_or("holder")
            .replace("did:web:", "")
    );
    let data = tempdir()?;
    std::fs::write(
        data.join("dev.cedar"),
        "@id(\"dev:allow\")\npermit (principal, action, resource);\n",
    )?;
    let mut b = remit_holder::Holder::builder(&id)
        .engine(engine.to_path_buf())
        .config(|cfg| {
            cfg.holder.dev = true;
            cfg.holder.listen = listen.to_string();
            cfg.holder.data_dir = data.display().to_string();
            cfg.policy.files = vec![data.join("dev.cedar").display().to_string()];
            cfg.examples.clear();
        });
    for (name, schema, batch, rc) in synthesize(&c, rows) {
        b = b
            .source_batches(&name, schema, vec![batch])
            .resource(&name, rc);
    }
    let h = b.build().await?;
    eprintln!(
        "remit dev: {id} on http://{listen} — synthetic data ({rows} rows/resource) from {}",
        catalog.display()
    );
    remit_holder::serve(h).await
}

fn tempdir() -> anyhow::Result<std::path::PathBuf> {
    let d = std::env::temp_dir().join(format!("remit-dev-{}", std::process::id()));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}
