# remit-read

Remit read plane: DataFusion integration, policy views, k-thresholds, limits, snapshot pinning.

The read plane: DataFusion with policy views (hidden columns, masks, row and owner filters), k-thresholds, differential-privacy rewrites, caps, snapshot pinning and full-text / kNN search. Sources: CSV, Parquet, NDJSON, SQLite, Postgres, Delta, Iceberg and any `TableProvider`; optional features add `duckdb`, `mysql`, `lance`, `tantivy` and `object-store` (`s3://`, `gs://`, `az://`).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
