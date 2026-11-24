//! Raw data loading. Connectors and credentials live only in the trusted
//! read plane. v0.1 loads each source into an immutable in-memory snapshot,
//! so every read is pinned to the snapshot's content hash by construction.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, BinaryBuilder, BooleanBuilder, Float64Builder, Int64Builder, StringBuilder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::{CsvReadOptions, JsonReadOptions, ParquetReadOptions, SessionContext};
use sha2::{Digest, Sha256};

use crate::config::SourceConfig;
use crate::ReadError;

/// One raw table snapshot.
#[derive(Clone, Debug)]
pub struct RawTable {
    pub schema: SchemaRef,
    pub batches: Arc<Vec<RecordBatch>>,
    /// Snapshot token recorded in receipts, e.g. `sha256:…` of the source bytes.
    pub version: String,
    pub rows: u64,
}

#[derive(Default, Debug, Clone)]
pub struct Store {
    tables: BTreeMap<String, RawTable>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tables(&self) -> impl Iterator<Item = (&String, &RawTable)> {
        self.tables.iter()
    }

    pub fn get(&self, name: &str) -> Option<&RawTable> {
        self.tables.get(name)
    }

    /// Insert in-memory Arrow data (the `memory` connector / Rust API).
    pub fn insert_batches(&mut self, name: &str, schema: SchemaRef, batches: Vec<RecordBatch>) {
        let mut h = Sha256::new();
        for b in &batches {
            let mut w = datafusion::arrow::ipc::writer::StreamWriter::try_new(Vec::new(), &schema)
                .expect("ipc");
            w.write(b).expect("ipc");
            w.finish().expect("ipc");
            h.update(w.into_inner().expect("ipc"));
        }
        let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
        let version = format!("mem:sha256:{}", &hex::encode(h.finalize())[..16]);
        self.tables.insert(
            name.to_lowercase(),
            RawTable {
                schema,
                batches: Arc::new(batches),
                version,
                rows,
            },
        );
    }

    /// Insert JSON rows (one object per row) as an in-memory table.
    pub fn insert_json(&mut self, name: &str, rows: &[serde_json::Value]) -> Result<(), ReadError> {
        use datafusion::arrow::json::reader::{infer_json_schema_from_iterator, ReaderBuilder};
        let e =
            |x: datafusion::arrow::error::ArrowError| ReadError::Config(format!("`{name}`: {x}"));
        let schema: SchemaRef =
            Arc::new(infer_json_schema_from_iterator(rows.iter().map(Ok)).map_err(e)?);
        let mut dec = ReaderBuilder::new(schema.clone())
            .build_decoder()
            .map_err(e)?;
        dec.serialize(rows).map_err(e)?;
        let batches = dec.flush().map_err(e)?.into_iter().collect();
        self.insert_batches(name, schema, batches);
        Ok(())
    }

    /// Load a configured source. Relative paths resolve against `base`.
    pub async fn load_source(&mut self, src: &SourceConfig, base: &Path) -> Result<(), ReadError> {
        if src.path.as_deref().is_some_and(|p| p.contains("://")) {
            #[cfg(feature = "object-store")]
            {
                let m = crate::remote::mirror(src).await?;
                let local = SourceConfig {
                    path: Some(m.path.clone()),
                    ..src.clone()
                };
                return Box::pin(self.load_source(&local, &m.dir)).await;
            }
            #[cfg(not(feature = "object-store"))]
            return Err(ReadError::Config(format!(
                "source `{}`: remote paths need the `object-store` feature",
                src.name
            )));
        }
        let ctx = SessionContext::new();
        match src.kind.as_str() {
            "csv" | "parquet" | "json" => {
                let pat = src.path.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `path`", src.name)))?;
                let files = expand(base, pat)?;
                if files.is_empty() {
                    return Err(ReadError::Config(format!("source `{}`: no files match `{pat}`", src.name)));
                }
                let table = src
                    .table
                    .clone()
                    .unwrap_or_else(|| files[0].file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "data".into()));
                let mut h = Sha256::new();
                for f in &files {
                    h.update(std::fs::read(f).map_err(|e| ReadError::Config(format!("{}: {e}", f.display())))?);
                }
                let paths: Vec<String> = files.iter().map(|p| p.to_string_lossy().to_string()).collect();
                let ext = files[0].extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
                let df = match src.kind.as_str() {
                    "csv" => ctx.read_csv(paths, CsvReadOptions::new().has_header(true).file_extension(&ext)).await,
                    "parquet" => ctx.read_parquet(paths, ParquetReadOptions { file_extension: &ext, ..Default::default() }).await,
                    _ => ctx.read_json(paths, JsonReadOptions { file_extension: &ext, ..Default::default() }).await,
                }
                .map_err(|e| ReadError::Config(format!("source `{}`: {e}", src.name)))?;
                let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
                let batches = df.collect().await.map_err(|e| ReadError::Config(e.to_string()))?;
                let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
                let version = format!("{}:sha256:{}", src.kind, hex::encode(h.finalize()));
                self.tables.insert(
                    format!("{}.{}", src.name, table).to_lowercase(),
                    RawTable { schema, batches: Arc::new(batches), version, rows },
                );
            }
            "sqlite" => {
                let path = src.path.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `path`", src.name)))?;
                let path = base.join(path);
                let tables = load_sqlite(&path, &src.tables)?;
                let mut hash = Sha256::new();
                for (name, (schema, batch)) in &tables {
                    hash.update((name.len() as u64).to_le_bytes());
                    hash.update(name.as_bytes());
                    let encoded = (|| -> Result<Vec<u8>, datafusion::arrow::error::ArrowError> {
                        let mut writer = datafusion::arrow::ipc::writer::StreamWriter::try_new(Vec::new(), schema)?;
                        writer.write(batch)?;
                        writer.finish()?;
                        writer.into_inner()
                    })().map_err(|e| ReadError::Config(e.to_string()))?;
                    hash.update((encoded.len() as u64).to_le_bytes());
                    hash.update(encoded);
                }
                let version = format!("sqlite:sha256:{}", hex::encode(hash.finalize()));
                for (t, (schema, batch)) in tables {
                    let rows = batch.num_rows() as u64;
                    self.tables.insert(
                        format!("{}.{}", src.name, t).to_lowercase(),
                        RawTable { schema, batches: Arc::new(vec![batch]), version: version.clone(), rows },
                    );
                }
            }
            "postgres" => {
                let dsn = src.dsn.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `dsn`", src.name)))?;
                let dsn = match dsn.strip_prefix("env:") {
                    Some(v) => std::env::var(v).map_err(|_| ReadError::Config(format!("source `{}`: env var {v} is not set", src.name)))?,
                    None => dsn.to_string(),
                };
                for (t, raw) in crate::postgres::load(&dsn, &src.tables).await? {
                    self.tables.insert(format!("{}.{}", src.name, t).to_lowercase(), raw);
                }
            }
            "duckdb" => {
                #[cfg(feature = "duckdb")]
                {
                    let path = src.path.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `path`", src.name)))?;
                    for (t, raw) in crate::duck::load(&base.join(path), &src.tables)? {
                        self.tables.insert(format!("{}.{}", src.name, t).to_lowercase(), raw);
                    }
                }
                #[cfg(not(feature = "duckdb"))]
                return Err(ReadError::Config("this build has no DuckDB backend (enable the `duckdb` feature)".into()));
            }
            "delta" | "iceberg" => {
                let path = src.path.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `path`", src.name)))?;
                let root = base.join(path);
                let raw = if src.kind == "delta" { crate::lakehouse::load_delta(&root, src.snapshot).await? } else { crate::lakehouse::load_iceberg(&root, src.snapshot).await? };
                let table = src.table.clone().unwrap_or_else(|| root.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "data".into()));
                self.tables.insert(format!("{}.{}", src.name, table).to_lowercase(), raw);
            }
            // A LanceDB table is a Lance dataset directory (`<db>/<table>.lance`).
            "lance" | "lancedb" => {
                #[cfg(feature = "lance")]
                {
                    let path = src.path.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `path`", src.name)))?;
                    let root = base.join(path);
                    let raw = crate::lance_db::load(&root, src.snapshot).await?;
                    let table = src.table.clone().unwrap_or_else(|| root.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "data".into()));
                    self.tables.insert(format!("{}.{}", src.name, table).to_lowercase(), raw);
                }
                #[cfg(not(feature = "lance"))]
                return Err(ReadError::Config("this build has no LanceDB backend (enable the `lance` feature)".into()));
            }
            "mysql" => {
                #[cfg(feature = "mysql")]
                {
                    let dsn = src.dsn.as_deref().ok_or_else(|| ReadError::Config(format!("source `{}` needs `dsn`", src.name)))?;
                    let dsn = match dsn.strip_prefix("env:") {
                        Some(v) => std::env::var(v).map_err(|_| ReadError::Config(format!("source `{}`: env var {v} is not set", src.name)))?,
                        None => dsn.to_string(),
                    };
                    for (t, raw) in crate::mysql::load(&dsn, &src.tables).await? {
                        self.tables.insert(format!("{}.{}", src.name, t).to_lowercase(), raw);
                    }
                }
                #[cfg(not(feature = "mysql"))]
                return Err(ReadError::Config("this build has no MySQL backend (enable the `mysql` feature)".into()));
            }
            // Loaded by the Holder (it speaks MCP, the read plane does not).
            "mcp" | "memory" => {}
            other => return Err(ReadError::Config(format!("unknown source kind `{other}` (csv|parquet|json|sqlite|postgres|mysql|duckdb|delta|iceberg|lance|mcp|memory)"))),
        }
        Ok(())
    }
}

fn expand(base: &Path, pat: &str) -> Result<Vec<PathBuf>, ReadError> {
    let full = if Path::new(pat).is_absolute() {
        PathBuf::from(pat)
    } else {
        base.join(pat)
    };
    let s = full.to_string_lossy().to_string();
    if !s.contains(['*', '?', '[']) {
        return Ok(vec![full]);
    }
    let mut out: Vec<PathBuf> = glob::glob(&s)
        .map_err(|e| ReadError::Config(e.to_string()))?
        .filter_map(Result::ok)
        .collect();
    out.sort();
    Ok(out)
}

fn load_sqlite(
    path: &Path,
    only: &[String],
) -> Result<Vec<(String, (SchemaRef, RecordBatch))>, ReadError> {
    let mut conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| ReadError::Config(format!("sqlite: {e}")))?;
    let conn = conn
        .transaction()
        .map_err(|e| ReadError::Config(e.to_string()))?;
    let mut names: Vec<String> = {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .map_err(|e| ReadError::Config(e.to_string()))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| ReadError::Config(e.to_string()))?;
        rows.filter_map(Result::ok).collect()
    };
    if !only.is_empty() {
        names.retain(|n| only.iter().any(|o| o.eq_ignore_ascii_case(n)));
    }
    let mut out = Vec::new();
    for t in names {
        let mut st = conn
            .prepare(&format!("SELECT * FROM \"{}\"", t.replace('"', "\"\"")))
            .map_err(|e| ReadError::Config(e.to_string()))?;
        let cols: Vec<(String, Option<String>)> = st
            .columns()
            .map(|c| {
                (
                    c.name().to_string(),
                    c.decl_type().map(|s| s.to_uppercase()),
                )
            })
            .collect();
        let types: Vec<DataType> = cols
            .iter()
            .map(|(_, d)| match d.as_deref() {
                Some(d) if d.contains("INT") => DataType::Int64,
                Some(d)
                    if d.contains("REAL")
                        || d.contains("FLOA")
                        || d.contains("DOUB")
                        || d.contains("NUMERIC")
                        || d.contains("DECIMAL") =>
                {
                    DataType::Float64
                }
                Some(d) if d.contains("BOOL") => DataType::Boolean,
                Some(d) if d.contains("BLOB") => DataType::Binary,
                _ => DataType::Utf8,
            })
            .collect();
        enum B {
            I(Int64Builder),
            F(Float64Builder),
            S(StringBuilder),
            Bo(BooleanBuilder),
            Bi(BinaryBuilder),
        }
        let mut builders: Vec<B> = types
            .iter()
            .map(|t| match t {
                DataType::Int64 => B::I(Int64Builder::new()),
                DataType::Float64 => B::F(Float64Builder::new()),
                DataType::Boolean => B::Bo(BooleanBuilder::new()),
                DataType::Binary => B::Bi(BinaryBuilder::new()),
                _ => B::S(StringBuilder::new()),
            })
            .collect();
        let mut rows = st.query([]).map_err(|e| ReadError::Config(e.to_string()))?;
        while let Some(r) = rows.next().map_err(|e| ReadError::Config(e.to_string()))? {
            for (i, b) in builders.iter_mut().enumerate() {
                use rusqlite::types::ValueRef as V;
                let v = r.get_ref(i).map_err(|e| ReadError::Config(e.to_string()))?;
                match (b, v) {
                    (B::I(b), V::Integer(x)) => b.append_value(x),
                    (B::I(b), V::Real(x)) => b.append_value(x as i64),
                    (B::I(b), _) => b.append_null(),
                    (B::F(b), V::Real(x)) => b.append_value(x),
                    (B::F(b), V::Integer(x)) => b.append_value(x as f64),
                    (B::F(b), _) => b.append_null(),
                    (B::Bo(b), V::Integer(x)) => b.append_value(x != 0),
                    (B::Bo(b), _) => b.append_null(),
                    (B::Bi(b), V::Blob(x)) => b.append_value(x),
                    (B::Bi(b), _) => b.append_null(),
                    (B::S(b), V::Text(x)) => b.append_value(String::from_utf8_lossy(x)),
                    (B::S(b), V::Integer(x)) => b.append_value(x.to_string()),
                    (B::S(b), V::Real(x)) => b.append_value(x.to_string()),
                    (B::S(b), _) => b.append_null(),
                }
            }
        }
        let arrays: Vec<ArrayRef> = builders
            .into_iter()
            .map(|b| -> ArrayRef {
                match b {
                    B::I(mut b) => Arc::new(b.finish()),
                    B::F(mut b) => Arc::new(b.finish()),
                    B::S(mut b) => Arc::new(b.finish()),
                    B::Bo(mut b) => Arc::new(b.finish()),
                    B::Bi(mut b) => Arc::new(b.finish()),
                }
            })
            .collect();
        let schema: SchemaRef = Arc::new(Schema::new(
            cols.iter()
                .zip(&types)
                .map(|((n, _), t)| Field::new(n, t.clone(), true))
                .collect::<Vec<_>>(),
        ));
        let batch = RecordBatch::try_new(schema.clone(), arrays)
            .map_err(|e| ReadError::Config(e.to_string()))?;
        out.push((t.to_lowercase(), (schema, batch)));
    }
    Ok(out)
}
