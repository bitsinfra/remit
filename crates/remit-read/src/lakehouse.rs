//! Delta Lake and Apache Iceberg tables on the local filesystem.
//!
//! Both readers resolve one table version to its exact set of data files and
//! load it as a pinned snapshot; the version token (`delta:v12`,
//! `iceberg:snapshot-…`) goes into receipts. Features that would change which
//! rows exist (deletion vectors, delete files, column mapping, schema
//! evolution) are refused rather than misread.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use serde_json::Value;

use crate::store::RawTable;
use crate::ReadError;

fn cfg(what: &str, e: impl std::fmt::Display) -> ReadError {
    ReadError::Config(format!("{what}: {e}"))
}

/// Resolve a table-relative (or `location`-prefixed) data path inside `root`.
fn inside(root: &Path, location: Option<&str>, p: &str) -> Result<PathBuf, ReadError> {
    let strip = |s: &str| s.strip_prefix("file://").unwrap_or(s).to_string();
    let p = strip(p);
    let rel = match location.map(strip) {
        Some(loc) => match p.strip_prefix(loc.trim_end_matches('/')) {
            Some(r) => r.trim_start_matches('/').to_string(),
            None => p.clone(),
        },
        None => p.clone(),
    };
    let decoded = percent_decode(&rel);
    let path = if Path::new(&decoded).is_absolute() {
        PathBuf::from(&decoded)
    } else {
        root.join(&decoded)
    };
    let canon = path
        .canonicalize()
        .map_err(|e| cfg(&format!("data file {}", path.display()), e))?;
    let root = root.canonicalize().map_err(|e| cfg("table root", e))?;
    if !canon.starts_with(&root) {
        return Err(ReadError::Config(format!(
            "data file {} is outside the table directory",
            canon.display()
        )));
    }
    Ok(canon)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(x) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(x);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

async fn read_parquet(
    files: &[PathBuf],
) -> Result<(Option<SchemaRef>, Vec<RecordBatch>), ReadError> {
    if files.is_empty() {
        return Ok((None, vec![]));
    }
    let ctx = SessionContext::new();
    let paths: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    // Keep `Utf8` so masks, search and lineage see one string type.
    let df = ctx
        .read_parquet(paths, ParquetReadOptions::default().skip_metadata(true))
        .await
        .map_err(|e| cfg("parquet", e))?;
    let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
    let batches = df.collect().await.map_err(|e| cfg("parquet", e))?;
    Ok((Some(schema), batches))
}

fn json_rows(batches: &[RecordBatch]) -> Result<Vec<Value>, ReadError> {
    let mut w = datafusion::arrow::json::LineDelimitedWriter::new(Vec::new());
    for b in batches {
        w.write(b).map_err(|e| cfg("checkpoint", e))?;
    }
    w.finish().map_err(|e| cfg("checkpoint", e))?;
    String::from_utf8_lossy(&w.into_inner())
        .lines()
        .map(|l| serde_json::from_str(l).map_err(|e| cfg("checkpoint", e)))
        .collect()
}

// ------------------------------------------------------------------- Delta

const DELTA_READER_FEATURES: &[&str] = &["timestampNtz", "vacuumProtocolCheck", "v2Checkpoint"];

pub async fn load_delta(root: &Path, pin: Option<i64>) -> Result<RawTable, ReadError> {
    let what = format!("delta {}", root.display());
    let log = root.join("_delta_log");
    let mut commits: BTreeMap<i64, PathBuf> = BTreeMap::new();
    let mut checkpoints: BTreeMap<i64, PathBuf> = BTreeMap::new();
    for e in std::fs::read_dir(&log)
        .map_err(|e| cfg(&what, e))?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().to_string();
        if let Some(v) = n.strip_suffix(".json").and_then(|v| v.parse().ok()) {
            commits.insert(v, e.path());
        } else if let Some(v) = n
            .strip_suffix(".checkpoint.parquet")
            .and_then(|v| v.parse().ok())
        {
            checkpoints.insert(v, e.path());
        }
    }
    let latest = commits
        .keys()
        .next_back()
        .copied()
        .ok_or_else(|| ReadError::Config(format!("{what}: empty log")))?;
    let version = pin.unwrap_or(latest);
    if version > latest {
        return Err(ReadError::Config(format!(
            "{what}: version {version} does not exist (latest {latest})"
        )));
    }
    let mut files: BTreeMap<String, Value> = BTreeMap::new();
    let mut meta: Option<Value> = None;
    let mut protocol: Option<Value> = None;
    let mut apply = |a: &Value| -> Result<(), ReadError> {
        if let Some(x) = a.get("add").filter(|x| x.is_object()) {
            if x.get("deletionVector").is_some_and(|d| !d.is_null()) {
                return Err(ReadError::Config(format!(
                    "{what}: deletion vectors are not supported"
                )));
            }
            files.insert(
                x["path"].as_str().unwrap_or("").to_string(),
                x["partitionValues"].clone(),
            );
        }
        if let Some(p) = a.get("remove").and_then(|x| x["path"].as_str()) {
            files.remove(p);
        }
        if let Some(m) = a.get("metaData").filter(|x| x.is_object()) {
            meta = Some(m.clone());
        }
        if let Some(p) = a.get("protocol").filter(|x| x.is_object()) {
            protocol = Some(p.clone());
        }
        Ok(())
    };
    let start = match checkpoints.range(..=version).next_back() {
        Some((v, p)) => {
            let (_, b) = read_parquet(std::slice::from_ref(p)).await?;
            for a in json_rows(&b)? {
                apply(&a)?;
            }
            v + 1
        }
        None => 0,
    };
    for v in start..=version {
        let p = commits
            .get(&v)
            .ok_or_else(|| ReadError::Config(format!("{what}: log entry {v} is missing")))?;
        for line in std::fs::read_to_string(p)
            .map_err(|e| cfg(&what, e))?
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            apply(&serde_json::from_str(line).map_err(|e| cfg(&what, e))?)?;
        }
    }
    let meta = meta.ok_or_else(|| ReadError::Config(format!("{what}: no metaData action")))?;
    if let Some(p) = &protocol {
        let min = p["minReaderVersion"].as_i64().unwrap_or(1);
        let feats: Vec<&str> = p["readerFeatures"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if min > 3 || min == 2 || feats.iter().any(|f| !DELTA_READER_FEATURES.contains(f)) {
            return Err(ReadError::Config(format!(
                "{what}: unsupported reader protocol {min} {feats:?}"
            )));
        }
    }
    if meta["configuration"]["delta.columnMapping.mode"]
        .as_str()
        .is_some_and(|m| m != "none")
    {
        return Err(ReadError::Config(format!(
            "{what}: column mapping is not supported"
        )));
    }
    let schema_json: Value = serde_json::from_str(meta["schemaString"].as_str().unwrap_or("{}"))
        .map_err(|e| cfg(&what, e))?;
    let parts: Vec<String> = meta["partitionColumns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    let ty_of = |name: &str| {
        schema_json["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|f| f["name"] == name)
            .and_then(|f| f["type"].as_str())
            .unwrap_or("string")
            .to_string()
    };
    // Group files by partition so each group is read once.
    let mut groups: BTreeMap<String, (Value, Vec<PathBuf>)> = BTreeMap::new();
    for (p, pv) in &files {
        groups
            .entry(pv.to_string())
            .or_insert_with(|| (pv.clone(), vec![]))
            .1
            .push(inside(root, None, p)?);
    }
    let ctx = SessionContext::new();
    let mut all: Option<datafusion::prelude::DataFrame> = None;
    for (pv, fs) in groups.into_values() {
        let paths: Vec<String> = fs.iter().map(|p| p.to_string_lossy().to_string()).collect();
        let mut df = ctx
            .read_parquet(paths, ParquetReadOptions::default())
            .await
            .map_err(|e| cfg(&what, e))?;
        for c in &parts {
            let v = pv[c.as_str()].as_str().map(String::from);
            let e = datafusion::logical_expr::lit(datafusion::scalar::ScalarValue::Utf8(v));
            let dt = delta_type(&ty_of(c))
                .ok_or_else(|| ReadError::Config(format!("{what}: partition type of `{c}`")))?;
            df = df
                .with_column(c, datafusion::logical_expr::cast(e, dt))
                .map_err(|e| cfg(&what, e))?;
        }
        let names: Vec<String> = schema_json["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f["name"].as_str().map(String::from))
            .collect();
        let cols: Vec<datafusion::logical_expr::Expr> = names
            .iter()
            .map(|n| datafusion::logical_expr::col(datafusion::common::Column::new_unqualified(n)))
            .collect();
        df = df.select(cols).map_err(|e| cfg(&what, e))?;
        all = Some(match all {
            None => df,
            Some(a) => a.union(df).map_err(|e| cfg(&what, e))?,
        });
    }
    let df = all
        .ok_or_else(|| ReadError::Config(format!("{what}: version {version} has no data files")))?;
    let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
    let batches = df.collect().await.map_err(|e| cfg(&what, e))?;
    let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
    Ok(RawTable {
        schema,
        batches: Arc::new(batches),
        version: format!("delta:{}:v{version}", meta["id"].as_str().unwrap_or("?")),
        rows,
    })
}

fn delta_type(t: &str) -> Option<datafusion::arrow::datatypes::DataType> {
    use datafusion::arrow::datatypes::{DataType as D, TimeUnit};
    Some(match t {
        "string" => D::Utf8,
        "long" | "integer" | "short" | "byte" => D::Int64,
        "double" | "float" => D::Float64,
        "boolean" => D::Boolean,
        "date" => D::Date32,
        "timestamp" => D::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
        "timestamp_ntz" => D::Timestamp(TimeUnit::Millisecond, None),
        _ => return None,
    })
}

// ----------------------------------------------------------------- Iceberg

fn avro_records(path: &Path) -> Result<Vec<Value>, ReadError> {
    let what = format!("iceberg manifest {}", path.display());
    let f = std::fs::File::open(path).map_err(|e| cfg(&what, e))?;
    let r = apache_avro::Reader::new(std::io::BufReader::new(f)).map_err(|e| cfg(&what, e))?;
    r.map(|v| v.map_err(|e| cfg(&what, e)).map(|v| avro_json(&v)))
        .collect()
}

fn avro_json(v: &apache_avro::types::Value) -> Value {
    use apache_avro::types::Value as A;
    match v {
        A::Null => Value::Null,
        A::Boolean(b) => Value::from(*b),
        A::Int(i) => Value::from(*i),
        A::Long(i) => Value::from(*i),
        A::Float(f) => Value::from(*f as f64),
        A::Double(f) => Value::from(*f),
        A::String(s) | A::Enum(_, s) => Value::from(s.clone()),
        A::Union(_, b) => avro_json(b),
        A::Array(a) => Value::Array(a.iter().map(avro_json).collect()),
        A::Map(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), avro_json(v))).collect()),
        A::Record(f) => Value::Object(f.iter().map(|(k, v)| (k.clone(), avro_json(v))).collect()),
        _ => Value::Null,
    }
}

pub async fn load_iceberg(root: &Path, pin: Option<i64>) -> Result<RawTable, ReadError> {
    let what = format!("iceberg {}", root.display());
    let dir = root.join("metadata");
    let mut best: Option<(i64, i64, Value)> = None;
    for e in std::fs::read_dir(&dir)
        .map_err(|e| cfg(&what, e))?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().to_string();
        if !n.ends_with(".metadata.json") {
            continue;
        }
        let m: Value =
            serde_json::from_str(&std::fs::read_to_string(e.path()).map_err(|e| cfg(&what, e))?)
                .map_err(|e| cfg(&what, e))?;
        let key = (
            m["last-sequence-number"].as_i64().unwrap_or(0),
            m["last-updated-ms"].as_i64().unwrap_or(0),
        );
        if best.as_ref().is_none_or(|b| key > (b.0, b.1)) {
            best = Some((key.0, key.1, m));
        }
    }
    let (_, _, meta) = best.ok_or_else(|| ReadError::Config(format!("{what}: no metadata")))?;
    if meta["format-version"]
        .as_i64()
        .is_none_or(|v| !(1..=2).contains(&v))
    {
        return Err(ReadError::Config(format!(
            "{what}: unsupported format version"
        )));
    }
    if meta["schemas"].as_array().is_some_and(|s| s.len() > 1) {
        return Err(ReadError::Config(format!(
            "{what}: evolved schemas are not supported"
        )));
    }
    let sid = pin
        .or(meta["current-snapshot-id"].as_i64())
        .filter(|s| *s >= 0)
        .ok_or_else(|| ReadError::Config(format!("{what}: table has no snapshot")))?;
    let snap = meta["snapshots"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["snapshot-id"].as_i64() == Some(sid))
        .ok_or_else(|| ReadError::Config(format!("{what}: snapshot {sid} not found")))?;
    let loc = meta["location"].as_str();
    let list = inside(root, loc, snap["manifest-list"].as_str().unwrap_or(""))?;
    let mut files = Vec::new();
    for m in avro_records(&list)? {
        if m["content"].as_i64().unwrap_or(0) != 0 {
            return Err(ReadError::Config(format!(
                "{what}: delete files (merge-on-read) are not supported"
            )));
        }
        for entry in avro_records(&inside(
            root,
            loc,
            m["manifest_path"].as_str().unwrap_or(""),
        )?)? {
            if entry["status"].as_i64() == Some(2) {
                continue; // deleted
            }
            let f = &entry["data_file"];
            if f["content"].as_i64().unwrap_or(0) != 0 {
                return Err(ReadError::Config(format!(
                    "{what}: delete files (merge-on-read) are not supported"
                )));
            }
            if !f["file_format"]
                .as_str()
                .unwrap_or("")
                .eq_ignore_ascii_case("parquet")
            {
                return Err(ReadError::Config(format!(
                    "{what}: only Parquet data files are supported"
                )));
            }
            files.push(inside(root, loc, f["file_path"].as_str().unwrap_or(""))?);
        }
    }
    files.sort();
    files.dedup();
    let (schema, batches) = read_parquet(&files).await?;
    let schema = schema
        .ok_or_else(|| ReadError::Config(format!("{what}: snapshot {sid} has no data files")))?;
    let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
    Ok(RawTable {
        schema,
        batches: Arc::new(batches),
        version: format!(
            "iceberg:{}:snapshot-{sid}",
            meta["table-uuid"].as_str().unwrap_or("?")
        ),
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{Int64Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use serde_json::json;

    fn tmp(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("remit-lake-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn write(path: &Path, ids: &[i64]) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, false),
        ]));
        let b = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(ids.to_vec())),
                Arc::new(StringArray::from(
                    ids.iter().map(|i| format!("n{i}")).collect::<Vec<_>>(),
                )),
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.read_batch(b)
            .unwrap()
            .write_parquet(
                path.to_str().unwrap(),
                datafusion::dataframe::DataFrameWriteOptions::new().with_single_file_output(true),
                None,
            )
            .await
            .unwrap();
    }

    fn ids(t: &RawTable) -> Vec<i64> {
        let mut v: Vec<i64> = crate::arrowconv::batches_to_rows(&t.batches)
            .iter()
            .map(|r| r["id"].as_i64().unwrap())
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn delta_time_travel_partitions_and_refusals() {
        let d = tmp("delta");
        std::fs::create_dir_all(d.join("_delta_log")).unwrap();
        std::fs::create_dir_all(d.join("region=EMEA")).unwrap();
        write(&d.join("region=EMEA/a.parquet"), &[1, 2]).await;
        write(&d.join("b.parquet"), &[3]).await;
        let schema = json!({"type": "struct", "fields": [{"name": "id", "type": "long"}, {"name": "name", "type": "string"}, {"name": "region", "type": "string"}]}).to_string();
        let log = |v: i64, actions: Vec<Value>| {
            std::fs::write(
                d.join(format!("_delta_log/{v:020}.json")),
                actions
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .unwrap()
        };
        log(
            0,
            vec![
                json!({"protocol": {"minReaderVersion": 1, "minWriterVersion": 2}}),
                json!({"metaData": {"id": "t1", "schemaString": schema, "partitionColumns": ["region"], "configuration": {}}}),
                json!({"add": {"path": "region=EMEA/a.parquet", "partitionValues": {"region": "EMEA"}}}),
            ],
        );
        log(
            1,
            vec![json!({"add": {"path": "b.parquet", "partitionValues": {"region": null}}})],
        );
        log(
            2,
            vec![json!({"remove": {"path": "region=EMEA/a.parquet"}})],
        );
        let t0 = load_delta(&d, Some(0)).await.unwrap();
        assert_eq!((ids(&t0), t0.version.as_str()), (vec![1, 2], "delta:t1:v0"));
        assert_eq!(
            crate::arrowconv::batches_to_rows(&t0.batches)[0]["region"],
            "EMEA"
        );
        assert_eq!(ids(&load_delta(&d, Some(1)).await.unwrap()), vec![1, 2, 3]);
        let t = load_delta(&d, None).await.unwrap();
        assert_eq!((ids(&t), t.version.as_str()), (vec![3], "delta:t1:v2"));
        assert!(crate::arrowconv::batches_to_rows(&t.batches)[0]["region"].is_null());
        assert!(load_delta(&d, Some(9)).await.is_err());
        log(
            3,
            vec![
                json!({"add": {"path": "b.parquet", "partitionValues": {"region": null}, "deletionVector": {"storageType": "u"}}}),
            ],
        );
        assert!(load_delta(&d, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("deletion vectors"));
        log(
            3,
            vec![
                json!({"add": {"path": "../../../../etc/passwd", "partitionValues": {"region": null}}}),
            ],
        );
        assert!(load_delta(&d, None).await.is_err(), "path escape");
        log(
            3,
            vec![
                json!({"protocol": {"minReaderVersion": 3, "minWriterVersion": 7, "readerFeatures": ["columnMapping"]}}),
            ],
        );
        assert!(load_delta(&d, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("protocol"));
    }

    #[tokio::test]
    async fn iceberg_snapshots_and_refusals() {
        use apache_avro::{types::Record, Schema as Av, Writer};
        let d = tmp("iceberg");
        std::fs::create_dir_all(d.join("metadata")).unwrap();
        std::fs::create_dir_all(d.join("data")).unwrap();
        write(&d.join("data/a.parquet"), &[1, 2]).await;
        write(&d.join("data/b.parquet"), &[3]).await;
        let loc = format!("file://{}", d.display());
        let entry = Av::parse_str(r#"{"type":"record","name":"manifest_entry","fields":[{"name":"status","type":"int"},{"name":"data_file","type":{"type":"record","name":"r2","fields":[{"name":"content","type":"int"},{"name":"file_path","type":"string"},{"name":"file_format","type":"string"}]}}]}"#).unwrap();
        let list = Av::parse_str(r#"{"type":"record","name":"manifest_file","fields":[{"name":"manifest_path","type":"string"},{"name":"content","type":"int"}]}"#).unwrap();
        let manifest = |name: &str, files: &[(i32, &str, i32)]| {
            let mut w = Writer::new(&entry, Vec::new());
            for (st, f, content) in files {
                let df = apache_avro::types::Value::Record(vec![
                    ("content".into(), (*content).into()),
                    ("file_path".into(), format!("{loc}/data/{f}").into()),
                    ("file_format".into(), "PARQUET".to_string().into()),
                ]);
                let mut r = Record::new(&entry).unwrap();
                r.put("status", *st);
                r.put("data_file", df);
                w.append(r).unwrap();
            }
            std::fs::write(d.join("metadata").join(name), w.into_inner().unwrap()).unwrap();
        };
        let listing = |name: &str, ms: &[(&str, i32)]| {
            let mut w = Writer::new(&list, Vec::new());
            for (m, c) in ms {
                let mut r = Record::new(&list).unwrap();
                r.put("manifest_path", format!("{loc}/metadata/{m}"));
                r.put("content", *c);
                w.append(r).unwrap();
            }
            std::fs::write(d.join("metadata").join(name), w.into_inner().unwrap()).unwrap();
        };
        manifest("m1.avro", &[(1, "a.parquet", 0)]);
        manifest("m2.avro", &[(2, "a.parquet", 0), (1, "b.parquet", 0)]);
        manifest("m3.avro", &[(1, "b.parquet", 1)]);
        listing("l1.avro", &[("m1.avro", 0)]);
        listing("l2.avro", &[("m2.avro", 0)]);
        listing("l3.avro", &[("m2.avro", 0), ("m3.avro", 1)]);
        let meta = |current: i64, seq: i64, file: &str| {
            let snaps: Vec<Value> = [(1, "l1.avro"), (2, "l2.avro"), (3, "l3.avro")].iter().map(|(i, l)| json!({"snapshot-id": i, "manifest-list": format!("{loc}/metadata/{l}")})).collect();
            std::fs::write(d.join("metadata").join(file), json!({"format-version": 2, "table-uuid": "u", "location": loc, "last-sequence-number": seq, "last-updated-ms": seq, "current-snapshot-id": current, "schemas": [{}], "snapshots": snaps}).to_string()).unwrap();
        };
        meta(1, 1, "v1.metadata.json");
        meta(2, 2, "v2.metadata.json");
        let t = load_iceberg(&d, None).await.unwrap();
        assert_eq!(
            (ids(&t), t.version.as_str()),
            (vec![3], "iceberg:u:snapshot-2")
        );
        assert_eq!(ids(&load_iceberg(&d, Some(1)).await.unwrap()), vec![1, 2]);
        assert!(load_iceberg(&d, Some(3))
            .await
            .unwrap_err()
            .to_string()
            .contains("delete files"));
        assert!(load_iceberg(&d, Some(4)).await.is_err());
    }
}
