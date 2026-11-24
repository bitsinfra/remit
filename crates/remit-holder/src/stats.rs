//! Statistics profiles: coarse, DP-noised descriptions of each resource,
//! computed **once** with a small, separately budgeted ε: the result is persisted
//! in the Holder's data dir and reused across restarts and refreshes (recomputing
//! would spend the ε again). Each privacy unit contributes at most one row. They address the
//! PySyft lesson that clean mock data misleads authors about long-tailed
//! real data. Buckets are data-independent so only counts are noised.

use std::collections::{BTreeMap, HashSet};

use datafusion::arrow::array::{Array, AsArray};
use datafusion::arrow::datatypes::*;
use datafusion::arrow::record_batch::RecordBatch;
use remit_read::{ReadPlane, ResourceConfig};
use serde_json::{json, Value};

const NUM_EDGES: [f64; 13] = [
    -1e9, -1e6, -1e3, -1.0, 0.0, 1.0, 10.0, 100.0, 1e3, 1e4, 1e5, 1e6, 1e9,
];

fn noisy(n: u64, eps: f64) -> u64 {
    remit_emit::dp::noise_i64(n as i64, 1.0, eps)
        .unwrap_or(n as i64)
        .max(0) as u64
}

/// The persisted profile, or a fresh one-time computation.
pub fn load_or_compute(
    path: &std::path::Path,
    plane: &ReadPlane,
    resources: &BTreeMap<String, ResourceConfig>,
    epsilon: f64,
) -> std::io::Result<Value> {
    if let Ok(s) = std::fs::read_to_string(path) {
        // A damaged file is not silently replaced: that would be a second spend.
        return serde_json::from_str(&s).map_err(std::io::Error::other);
    }
    let v = profiles(plane, resources, epsilon);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, v.to_string())?;
    std::fs::rename(&tmp, path)?;
    Ok(v)
}

/// One row per privacy unit (the first), so every count has sensitivity 1.
fn one_row_per_unit(batches: &[RecordBatch], unit: Option<&str>) -> Vec<RecordBatch> {
    let Some(u) = unit else {
        return batches.to_vec();
    };
    let mut seen: HashSet<String> = HashSet::new();
    batches
        .iter()
        .map(|b| {
            let Ok(i) = b.schema().index_of(u) else {
                return b.clone();
            };
            let keep: datafusion::arrow::array::BooleanArray =
                (0..b.num_rows())
                    .map(|r| {
                        Some(seen.insert(
                            remit_read::arrowconv::cell(b.column(i).as_ref(), r).to_string(),
                        ))
                    })
                    .collect();
            datafusion::arrow::compute::filter_record_batch(b, &keep)
                .unwrap_or_else(|_| b.slice(0, 0))
        })
        .collect()
}

pub fn profiles(
    plane: &ReadPlane,
    resources: &BTreeMap<String, ResourceConfig>,
    epsilon: f64,
) -> Value {
    let mut out = serde_json::Map::new();
    let total_cols: usize = resources
        .keys()
        .filter_map(|t| plane.exposed_schema(t))
        .map(|s| s.fields().len() + 1)
        .sum();
    if total_cols == 0 || epsilon <= 0.0 {
        return Value::Object(out);
    }
    let eps = epsilon / total_cols as f64;
    for t in resources.keys() {
        let (Some(schema), Some(batches)) = (plane.exposed_schema(t), plane.raw_batches(t)) else {
            continue;
        };
        let batches = one_row_per_unit(
            &batches,
            resources.get(t).and_then(|r| r.privacy_unit.as_deref()),
        );
        let noisy_rows = noisy(batches.iter().map(|b| b.num_rows() as u64).sum(), eps);
        let mut cols = serde_json::Map::new();
        for f in schema.fields() {
            let r = resources.get(t).map(|r| r.column(f.name()));
            if r.as_ref().is_some_and(|c| c.mask.is_some()) {
                continue;
            }
            let mut nulls = 0u64;
            let mut hist = vec![0u64; NUM_EDGES.len() + 1];
            let mut years: BTreeMap<i32, u64> = BTreeMap::new();
            let mut lens = [0u64; 4];
            let mut distinct: HashSet<String> = HashSet::new();
            let mut kind = "other";
            for b in batches.iter() {
                let Ok(i) = b.schema().index_of(f.name()) else {
                    continue;
                };
                let a = b.column(i);
                nulls += a.null_count() as u64;
                match a.data_type() {
                    DataType::Int64
                    | DataType::Int32
                    | DataType::Float64
                    | DataType::Float32
                    | DataType::UInt64 => {
                        kind = "number";
                        let c = datafusion::arrow::compute::cast(a, &DataType::Float64).unwrap();
                        let c = c.as_primitive::<Float64Type>();
                        for v in c.iter().flatten() {
                            let ix = NUM_EDGES
                                .iter()
                                .position(|e| v < *e)
                                .unwrap_or(NUM_EDGES.len());
                            hist[ix] += 1;
                        }
                    }
                    DataType::Timestamp(_, _) | DataType::Date32 => {
                        kind = "time";
                        let c = datafusion::arrow::compute::cast(
                            a,
                            &DataType::Timestamp(TimeUnit::Millisecond, None),
                        )
                        .unwrap();
                        for v in c
                            .as_primitive::<TimestampMillisecondType>()
                            .iter()
                            .flatten()
                        {
                            let y = 1970 + (v / 31_556_952_000) as i32;
                            *years.entry(y.clamp(1990, 2060)).or_default() += 1;
                        }
                    }
                    DataType::Utf8 => {
                        kind = "string";
                        let s = a.as_string::<i32>();
                        for v in s.iter().flatten() {
                            let l = v.chars().count();
                            lens[if l < 8 {
                                0
                            } else if l < 32 {
                                1
                            } else if l < 128 {
                                2
                            } else {
                                3
                            }] += 1;
                            if distinct.len() < 100_000 {
                                distinct.insert(v.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Split this column's ε between null rate and its histogram.
            let e2 = eps / 2.0;
            let null_rate = (noisy(nulls, e2) as f64 / noisy_rows.max(1) as f64).min(1.0);
            let mut c = json!({"kind": kind, "null_rate": (null_rate * 100.0).round() / 100.0});
            match kind {
                "number" => {
                    let mut buckets = Vec::new();
                    for (i, n) in hist.iter().enumerate() {
                        let lo = if i == 0 {
                            Value::Null
                        } else {
                            json!(NUM_EDGES[i - 1])
                        };
                        let hi = if i == NUM_EDGES.len() {
                            Value::Null
                        } else {
                            json!(NUM_EDGES[i])
                        };
                        let nn = noisy(*n, e2);
                        if nn > 0 {
                            buckets.push(
                                json!({"gte": lo, "lt": hi, "count": remit_analyze::bucket(nn)}),
                            );
                        }
                    }
                    c["histogram"] = json!(buckets);
                }
                "time" => {
                    // Every year of a fixed range is noised, so which years appear
                    // is not itself information about the data.
                    let floor = (4.0 / e2).ceil() as u64;
                    let b: Vec<Value> = (1990..=2060)
                        .filter_map(|y: i32| {
                            let nn = noisy(years.get(&y).copied().unwrap_or(0), e2);
                            (nn > floor)
                                .then(|| json!({"year": y, "count": remit_analyze::bucket(nn)}))
                        })
                        .collect();
                    c["years"] = json!(b);
                }
                "string" => {
                    c["length"] = json!({"<8": remit_analyze::bucket(noisy(lens[0], e2 / 2.0)), "8-31": remit_analyze::bucket(noisy(lens[1], e2 / 2.0)),
                        "32-127": remit_analyze::bucket(noisy(lens[2], e2 / 2.0)), "≥128": remit_analyze::bucket(noisy(lens[3], e2 / 2.0))});
                    c["distinct"] = json!(remit_analyze::bucket(noisy(
                        distinct.len() as u64,
                        e2 / 2.0
                    )));
                }
                _ => {}
            }
            cols.insert(f.name().clone(), c);
        }
        out.insert(t.clone(), json!({"rows": remit_analyze::bucket(noisy_rows), "columns": cols, "epsilon_spent": epsilon}));
    }
    Value::Object(out)
}
