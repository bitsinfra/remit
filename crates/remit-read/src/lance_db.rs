//! LanceDB tables (Lance datasets). A dataset version is loaded as a pinned
//! snapshot; the version is the data-version token. Vector columns
//! (`FixedSizeList<Float32>`) feed `knn` indexes.

use std::path::Path;
use std::sync::Arc;

use futures::TryStreamExt;
use lance::dataset::Dataset;

use crate::store::RawTable;
use crate::ReadError;

pub async fn load(path: &Path, pin: Option<i64>) -> Result<RawTable, ReadError> {
    let e = |x: lance::Error| ReadError::Config(format!("lance {}: {x}", path.display()));
    let mut ds = Dataset::open(&path.to_string_lossy()).await.map_err(e)?;
    if let Some(v) = pin {
        ds = ds.checkout_version(v as u64).await.map_err(e)?;
    }
    let version = format!("lance:v{}", ds.version().version);
    let x = |m: String| ReadError::Config(format!("lance {}: {m}", path.display()));
    let schema58 = lance::deps::arrow_schema::Schema::from(ds.schema());
    let mut stream = ds
        .scan()
        .scan_in_order(true)
        .try_into_stream()
        .await
        .map_err(e)?;
    let mut buf = Vec::new();
    {
        let mut w = arrow_ipc_lance::writer::StreamWriter::try_new(&mut buf, &schema58)
            .map_err(|e| x(e.to_string()))?;
        while let Some(b) = stream.try_next().await.map_err(e)? {
            w.write(&b).map_err(|e| x(e.to_string()))?;
        }
        w.finish().map_err(|e| x(e.to_string()))?;
    }
    let r = datafusion::arrow::ipc::reader::StreamReader::try_new(std::io::Cursor::new(buf), None)
        .map_err(|e| x(e.to_string()))?;
    let schema = r.schema();
    let batches = r
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| x(e.to_string()))?;
    let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
    Ok(RawTable {
        schema,
        batches: Arc::new(batches),
        version,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lance::dataset::{WriteMode, WriteParams};
    use lance::deps::arrow_array::types::Float32Type;
    use lance::deps::arrow_array::{
        FixedSizeListArray, RecordBatch, RecordBatchIterator, StringArray,
    };
    use lance::deps::arrow_schema::{DataType, Field, Schema};

    async fn write(path: &str, ids: Vec<&str>, v: Vec<[f32; 2]>, mode: WriteMode) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("doc_id", DataType::Utf8, false),
            Field::new(
                "emb",
                DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), 2),
                true,
            ),
        ]));
        let emb = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            v.into_iter().map(|p| Some(p.map(Some))),
            2,
        );
        let b = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(ids)), Arc::new(emb)],
        )
        .unwrap();
        let p = WriteParams {
            mode,
            ..Default::default()
        };
        Dataset::write(RecordBatchIterator::new([Ok(b)], schema), path, Some(p))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lance_versions_pin_and_vectors_search() {
        let dir = std::env::temp_dir().join(format!("remit-lance-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = dir.join("docs.lance");
        write(
            &t.to_string_lossy(),
            vec!["a", "b"],
            vec![[1.0, 0.0], [0.0, 1.0]],
            WriteMode::Create,
        )
        .await;
        write(
            &t.to_string_lossy(),
            vec!["c"],
            vec![[0.9, 0.1]],
            WriteMode::Append,
        )
        .await;
        let latest = load(&t, None).await.unwrap();
        assert_eq!((latest.rows, latest.version.as_str()), (3, "lance:v2"));
        let pinned = load(&t, Some(1)).await.unwrap();
        assert_eq!((pinned.rows, pinned.version.as_str()), (2, "lance:v1"));
        assert!(load(&t, Some(9)).await.is_err());

        let cfg = crate::search::IndexConfig {
            name: "emb".into(),
            kind: "vector".into(),
            table: "docs.docs".into(),
            id_column: "doc_id".into(),
            text_column: None,
            vector_column: Some("emb".into()),
            engine: None,
        };
        let ix = crate::search::SearchIndex::build(&cfg, &latest).unwrap();
        let hits: Vec<_> = ix
            .knn(&[1.0, 0.0], 2, None)
            .into_iter()
            .map(|h| h.0)
            .collect();
        assert_eq!(hits, vec!["a", "c"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
