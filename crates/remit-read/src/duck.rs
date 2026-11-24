//! Native DuckDB-file connector. Tables are read in one read-only
//! connection into an immutable snapshot (version = sha256 of the file), and
//! batches cross from DuckDB's Arrow to DataFusion's via Arrow IPC.

use std::path::Path;
use std::sync::Arc;

use datafusion::arrow::ipc::reader::StreamReader;
use datafusion::arrow::record_batch::RecordBatch;
use sha2::{Digest, Sha256};

use crate::store::RawTable;
use crate::ReadError;

fn cfg(e: impl std::fmt::Display) -> ReadError {
    ReadError::Config(format!("duckdb: {e}"))
}

pub fn load(path: &Path, only: &[String]) -> Result<Vec<(String, RawTable)>, ReadError> {
    let bytes = std::fs::read(path).map_err(|e| cfg(format!("{}: {e}", path.display())))?;
    let version = format!("duckdb:sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let conn = duckdb::Connection::open_with_flags(
        path,
        duckdb::Config::default()
            .access_mode(duckdb::AccessMode::ReadOnly)
            .map_err(cfg)?,
    )
    .map_err(cfg)?;
    let mut names: Vec<String> = {
        let mut st = conn.prepare("SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' ORDER BY 1").map_err(cfg)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(cfg)?;
        rows.filter_map(Result::ok).collect()
    };
    if !only.is_empty() {
        names.retain(|n| {
            only.iter().any(|o| {
                o.eq_ignore_ascii_case(n)
                    || n.rsplit('.')
                        .next()
                        .is_some_and(|t| t.eq_ignore_ascii_case(o))
            })
        });
    }
    let mut out = Vec::new();
    for full in names {
        let q = format!(
            "SELECT * FROM {}",
            full.split('.')
                .map(|p| format!("\"{}\"", p.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(".")
        );
        let mut st = conn.prepare(&q).map_err(cfg)?;
        let arrow = st.query_arrow([]).map_err(cfg)?;
        let dschema = arrow.get_schema();
        let mut buf = Vec::new();
        {
            let mut w =
                arrow60_ipc::writer::StreamWriter::try_new(&mut buf, &dschema).map_err(cfg)?;
            for b in arrow {
                w.write(&b).map_err(cfg)?;
            }
            w.finish().map_err(cfg)?;
        }
        let reader = StreamReader::try_new(std::io::Cursor::new(buf), None).map_err(cfg)?;
        let schema = reader.schema();
        let batches: Vec<RecordBatch> = reader.collect::<Result<_, _>>().map_err(cfg)?;
        let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
        let t = full.rsplit('.').next().unwrap_or(&full).to_lowercase();
        out.push((
            t,
            RawTable {
                schema,
                batches: Arc::new(batches),
                version: version.clone(),
                rows,
            },
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn loads_a_duckdb_file() {
        let dir = std::env::temp_dir().join(format!("remit-duck-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.duckdb");
        let _ = std::fs::remove_file(&p);
        {
            let c = duckdb::Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE accounts (id VARCHAR, region VARCHAR, arr DOUBLE, created TIMESTAMP); INSERT INTO accounts VALUES ('a', 'EMEA', 10.5, '2026-01-01 00:00:00'), ('b', 'AMER', 3.0, '2026-02-01 00:00:00');").unwrap();
        }
        let t = super::load(&p, &[]).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, "accounts");
        assert_eq!(t[0].1.rows, 2);
        assert!(t[0].1.version.starts_with("duckdb:sha256:"));
    }
}
