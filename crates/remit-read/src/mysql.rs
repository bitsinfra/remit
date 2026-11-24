//! MySQL / MariaDB connector (feature `mysql`). Tables are loaded inside one
//! `START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY`, so every table
//! comes from the same InnoDB read view; the executed GTID set (or binlog
//! position) is the data-version token; without either, the version is a hash
//! of the loaded rows.

use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, Float64Builder, Int64Builder, StringBuilder, TimestampMillisecondBuilder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use mysql_async::consts::ColumnType as C;
use mysql_async::prelude::Queryable;
use mysql_async::{Row, Value as V};

use crate::store::RawTable;
use crate::ReadError;

fn cfg(e: impl std::fmt::Display) -> ReadError {
    ReadError::Config(format!("mysql: {e}"))
}

fn ident(s: &str) -> String {
    s.split('.')
        .map(|p| format!("`{}`", p.replace('`', "``")))
        .collect::<Vec<_>>()
        .join(".")
}

fn text(v: &V) -> Option<String> {
    match v {
        V::NULL => None,
        V::Bytes(b) => Some(String::from_utf8_lossy(b).to_string()),
        V::Int(i) => Some(i.to_string()),
        V::UInt(i) => Some(i.to_string()),
        V::Float(f) => Some(f.to_string()),
        V::Double(f) => Some(f.to_string()),
        V::Date(y, mo, d, h, mi, s, us) => Some(format!(
            "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z",
            us / 1000
        )),
        V::Time(neg, d, h, m, s, _) => Some(format!(
            "{}{:02}:{m:02}:{s:02}",
            if *neg { "-" } else { "" },
            *d * 24 + *h as u32
        )),
    }
}

fn content_version(schema: &Schema, batch: &RecordBatch) -> Result<String, ReadError> {
    use sha2::Digest;
    let mut w =
        datafusion::arrow::ipc::writer::StreamWriter::try_new(Vec::new(), schema).map_err(cfg)?;
    w.write(batch).map_err(cfg)?;
    let bytes = w.into_inner().map_err(cfg)?;
    Ok(format!(
        "mysql-sha256:{}",
        &hex::encode(sha2::Sha256::digest(bytes))[..32]
    ))
}

pub async fn load(dsn: &str, tables: &[String]) -> Result<Vec<(String, RawTable)>, ReadError> {
    if tables.is_empty() {
        return Err(ReadError::Config(
            "mysql source needs `tables = [...]`".into(),
        ));
    }
    let pool = mysql_async::Pool::from_url(dsn).map_err(cfg)?;
    let mut c = pool.get_conn().await.map_err(cfg)?;
    c.query_drop("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .await
        .map_err(cfg)?;
    c.query_drop("SET time_zone = '+00:00'")
        .await
        .map_err(cfg)?;
    c.query_drop("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
        .await
        .map_err(cfg)?;
    let gtid: Option<String> = c
        .query_first("SELECT @@GLOBAL.gtid_executed")
        .await
        .ok()
        .flatten();
    let version = match gtid.filter(|g| !g.is_empty()) {
        Some(g) => format!("mysql-gtid:{}", g.replace(['\n', ' '], "")),
        None => {
            let pos: Option<Row> = match c.query_first("SHOW BINARY LOG STATUS").await {
                Ok(r) => r,
                Err(_) => c.query_first("SHOW MASTER STATUS").await.ok().flatten(),
            };
            match pos {
                Some(r) => format!(
                    "mysql-binlog:{}:{}",
                    r.as_ref(0).and_then(text).unwrap_or_default(),
                    r.as_ref(1).and_then(text).unwrap_or_default()
                ),
                None => String::new(),
            }
        }
    };
    let mut out = Vec::new();
    for t in tables {
        let rows: Vec<Row> = c
            .query(format!("SELECT * FROM {}", ident(t)))
            .await
            .map_err(cfg)?;
        let cols = match rows.first() {
            Some(r) => r.columns(),
            None => {
                let st = c
                    .prep(format!("SELECT * FROM {}", ident(t)))
                    .await
                    .map_err(cfg)?;
                st.columns().to_vec().into()
            }
        };
        let (mut fields, mut arrays): (Vec<Field>, Vec<ArrayRef>) = (vec![], vec![]);
        for (i, col) in cols.iter().enumerate() {
            let get = |r: &Row| r.as_ref(i).cloned().unwrap_or(V::NULL);
            let (dt, arr): (DataType, ArrayRef) = match col.column_type() {
                C::MYSQL_TYPE_TINY
                | C::MYSQL_TYPE_SHORT
                | C::MYSQL_TYPE_LONG
                | C::MYSQL_TYPE_LONGLONG
                | C::MYSQL_TYPE_INT24
                | C::MYSQL_TYPE_YEAR => {
                    let mut b = Int64Builder::new();
                    for r in &rows {
                        // BIGINT UNSIGNED beyond i64 is refused, not read as NULL.
                        b.append_option(
                            text(&get(r))
                                .map(|s| s.parse::<i64>())
                                .transpose()
                                .map_err(|e| cfg(format!("`{t}`.`{}`: {e}", col.name_str())))?,
                        );
                    }
                    (DataType::Int64, Arc::new(b.finish()))
                }
                C::MYSQL_TYPE_FLOAT
                | C::MYSQL_TYPE_DOUBLE
                | C::MYSQL_TYPE_DECIMAL
                | C::MYSQL_TYPE_NEWDECIMAL => {
                    let mut b = Float64Builder::new();
                    rows.iter()
                        .for_each(|r| b.append_option(text(&get(r)).and_then(|s| s.parse().ok())));
                    (DataType::Float64, Arc::new(b.finish()))
                }
                C::MYSQL_TYPE_TIMESTAMP | C::MYSQL_TYPE_DATETIME | C::MYSQL_TYPE_DATE => {
                    let mut b = TimestampMillisecondBuilder::new().with_timezone("UTC");
                    rows.iter().for_each(|r| {
                        b.append_option(text(&get(r)).and_then(|s| {
                            let s = s.replace(' ', "T");
                            let s = if s.len() == 10 {
                                format!("{s}T00:00:00Z")
                            } else if s.ends_with('Z') {
                                s
                            } else {
                                format!("{s}Z")
                            };
                            remit_types::parse_timestamp_ms(&s)
                        }))
                    });
                    (
                        DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                        Arc::new(b.finish()),
                    )
                }
                _ => {
                    let mut b = StringBuilder::new();
                    rows.iter().for_each(|r| b.append_option(text(&get(r))));
                    (DataType::Utf8, Arc::new(b.finish()))
                }
            };
            fields.push(Field::new(col.name_str(), dt, true));
            arrays.push(arr);
        }
        let schema: SchemaRef = Arc::new(Schema::new(fields));
        let batch = RecordBatch::try_new(schema.clone(), arrays).map_err(cfg)?;
        let n = batch.num_rows() as u64;
        out.push((
            t.rsplit('.').next().unwrap_or(t).to_lowercase(),
            RawTable {
                version: if version.is_empty() {
                    content_version(&schema, &batch)?
                } else {
                    version.clone()
                },
                schema,
                batches: Arc::new(vec![batch]),
                rows: n,
            },
        ));
    }
    c.query_drop("COMMIT").await.map_err(cfg)?;
    drop(c);
    pool.disconnect().await.map_err(cfg)?;
    Ok(out)
}
