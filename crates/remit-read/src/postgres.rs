//! Postgres connector. Each configured table is loaded inside one
//! `REPEATABLE READ READ ONLY` transaction, so all tables come from the same
//! MVCC snapshot; the snapshot id and WAL LSN are the data-version token
//! recorded in receipts (`pg-snapshot:<xmin:xmax:xip>@<lsn>`). Credentials
//! never leave the trusted read plane.

use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, BooleanBuilder, Date32Builder, Float64Builder, Int64Builder, StringBuilder,
    TimestampMillisecondBuilder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use tokio_postgres::types::Type;

use crate::store::RawTable;
use crate::ReadError;

fn cfg(e: impl std::fmt::Display) -> ReadError {
    ReadError::Config(format!("postgres: {e}"))
}

fn ident(s: &str) -> String {
    s.split('.')
        .map(|p| format!("\"{}\"", p.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(".")
}

pub async fn load(dsn: &str, tables: &[String]) -> Result<Vec<(String, RawTable)>, ReadError> {
    if tables.is_empty() {
        return Err(ReadError::Config(
            "postgres source needs `tables = [...]`".into(),
        ));
    }
    let (mut client, conn) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .map_err(cfg)?;
    let h = tokio::spawn(async move {
        let _ = conn.await;
    });
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(cfg)?;
    let snap: String = tx
        .query_one("SELECT pg_current_snapshot()::text", &[])
        .await
        .map_err(cfg)?
        .get(0);
    let lsn: Option<String> = tx.query_one("SELECT CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()::text ELSE pg_current_wal_lsn()::text END", &[]).await.ok().map(|r| r.get(0));
    let version = format!("pg-snapshot:{snap}@{}", lsn.unwrap_or_default());
    let mut out = Vec::new();
    for t in tables {
        let stmt = tx
            .prepare(&format!("SELECT * FROM {} LIMIT 0", ident(t)))
            .await
            .map_err(cfg)?;
        let cols = stmt.columns();
        let projection = cols
            .iter()
            .map(|c| {
                let name = format!("\"{}\"", c.name().replace('"', "\"\""));
                match *c.type_() {
                    Type::INT2
                    | Type::INT4
                    | Type::INT8
                    | Type::FLOAT4
                    | Type::FLOAT8
                    | Type::BOOL
                    | Type::TIMESTAMPTZ
                    | Type::TIMESTAMP
                    | Type::DATE => name,
                    _ => format!("{name}::text AS {name}"),
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let rows = tx
            .query(&format!("SELECT {projection} FROM {}", ident(t)), &[])
            .await
            .map_err(cfg)?;
        let mut fields = Vec::new();
        let mut arrays: Vec<ArrayRef> = Vec::new();
        for (i, c) in cols.iter().enumerate() {
            let (dt, arr): (DataType, ArrayRef) = match *c.type_() {
                Type::INT2 | Type::INT4 | Type::INT8 => {
                    let mut b = Int64Builder::new();
                    for r in &rows {
                        let v: Option<i64> = match *c.type_() {
                            Type::INT2 => r.get::<_, Option<i16>>(i).map(i64::from),
                            Type::INT4 => r.get::<_, Option<i32>>(i).map(i64::from),
                            _ => r.get::<_, Option<i64>>(i),
                        };
                        b.append_option(v);
                    }
                    (DataType::Int64, Arc::new(b.finish()))
                }
                Type::FLOAT4 | Type::FLOAT8 => {
                    let mut b = Float64Builder::new();
                    for r in &rows {
                        let v: Option<f64> = if *c.type_() == Type::FLOAT4 {
                            r.get::<_, Option<f32>>(i).map(f64::from)
                        } else {
                            r.get(i)
                        };
                        b.append_option(v);
                    }
                    (DataType::Float64, Arc::new(b.finish()))
                }
                Type::BOOL => {
                    let mut b = BooleanBuilder::new();
                    for r in &rows {
                        b.append_option(r.get::<_, Option<bool>>(i));
                    }
                    (DataType::Boolean, Arc::new(b.finish()))
                }
                Type::TIMESTAMPTZ => {
                    let mut b = TimestampMillisecondBuilder::new().with_timezone("UTC");
                    for r in &rows {
                        b.append_option(
                            r.get::<_, Option<chrono::DateTime<chrono::Utc>>>(i)
                                .map(|d| d.timestamp_millis()),
                        );
                    }
                    (
                        DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                        Arc::new(b.finish()),
                    )
                }
                Type::TIMESTAMP => {
                    let mut b = TimestampMillisecondBuilder::new().with_timezone("UTC");
                    for r in &rows {
                        b.append_option(
                            r.get::<_, Option<chrono::NaiveDateTime>>(i)
                                .map(|d| d.and_utc().timestamp_millis()),
                        );
                    }
                    (
                        DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                        Arc::new(b.finish()),
                    )
                }
                Type::DATE => {
                    let mut b = Date32Builder::new();
                    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
                    for r in &rows {
                        b.append_option(
                            r.get::<_, Option<chrono::NaiveDate>>(i)
                                .map(|d| (d - epoch).num_days() as i32),
                        );
                    }
                    (DataType::Date32, Arc::new(b.finish()))
                }
                _ => {
                    let mut b = StringBuilder::new();
                    for r in &rows {
                        b.append_option(r.get::<_, Option<String>>(i));
                    }
                    (DataType::Utf8, Arc::new(b.finish()))
                }
            };
            fields.push(Field::new(c.name(), dt, true));
            arrays.push(arr);
        }
        let schema: SchemaRef = Arc::new(Schema::new(fields));
        let batch = RecordBatch::try_new(schema.clone(), arrays).map_err(cfg)?;
        let n = batch.num_rows() as u64;
        let name = t.rsplit('.').next().unwrap_or(t).to_lowercase();
        out.push((
            name,
            RawTable {
                schema,
                batches: Arc::new(vec![batch]),
                version: version.clone(),
                rows: n,
            },
        ));
    }
    tx.commit().await.map_err(cfg)?;
    drop(client);
    h.abort();
    Ok(out)
}
