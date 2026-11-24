# Remit SQL

A strict, deterministic dialect profile over `sqlparser-rs` (PostgreSQL
dialect), lowered to a DataFusion `LogicalPlan`. The reference checker
(`remit-sql`) is shared by the Holder and the SDKs (`remit-verify-wasm`).

## Allowed

- A single `SELECT` statement (`RMT-E0202` otherwise), with `WHERE`, `GROUP BY`,
  `HAVING`, `ORDER BY`, `LIMIT`/`OFFSET`/`FETCH`, `DISTINCT`.
- `INNER`/`JOIN` and `LEFT [OUTER] JOIN`; comma joins.
- Non-recursive CTEs, derived tables and subqueries. Use `IN` and `EXISTS`
  subqueries in filters. To return a boolean for whether any rows match, use
  `SELECT COUNT(*) > 0 AS found FROM … WHERE …`.
- Relations named `source.table` from the principal's visible catalog.
- Allowlisted deterministic functions: arithmetic, string, date/time
  (`date_trunc`, `date_part`, `extract`, `date_bin`, `to_timestamp`, …),
  conditional (`coalesce`, `nullif`, `CASE`), casts; aggregates (`count`, `sum`,
  `avg`, `min`, `max`, `stddev*`, `var*`, `median`, `bool_and/or`, `corr`,
  `covar*`, `regr_*`, `string_agg`, `array_agg`); window functions
  (`row_number`, `rank`, `lag`, `lead`, …). The full list is
  `remit_sql::{SCALAR,AGGREGATE,WINDOW}_FUNCTIONS`.
- Named params `$name` (declared in the template, `RMT-E0110`).
- Holder search functions over catalog `indexes`: `fts('index', $q, k)` (BM25,
  light stemming) and `knn('index', $vector_json, k)` (cosine). They return only
  `(id, score)`; join back to the resource to read columns, so its policy view
  still applies. They need the `search` operation (a Cedar action) on the
  indexed resource; indexes cover exposed, unmasked columns only. The first
  argument must be a string literal naming an index (`RMT-E0211`).

## Excluded

| Construct | Code |
|---|---|
| DDL, DML, utility statements, multiple statements | `RMT-E0202` |
| `WITH RECURSIVE` | `RMT-E0203` |
| `UNION`/`INTERSECT`/`EXCEPT` | `RMT-E0204` (declare a second read instead) |
| `now()`, `current_*`, `random()`, `uuid()`, UDFs, qualified functions | `RMT-E0205` |
| `RIGHT`/`FULL`/`CROSS`/`SEMI`/`ANTI` joins, `APPLY` | `RMT-E0206` |
| `SELECT INTO`, locking, `TOP`, `QUALIFY`, `LATERAL`, sampling, time travel, dialect clauses | `RMT-E0207` |
| Positional params `$1` | `RMT-E0208` |
| Over-long statements (> 16 KiB) | `RMT-E0210` |

Time always comes from params. Diagnostics carry a 1-based `(line, column)` span
when known and a hint.

## Policy is enforced in the plan

Senders' SQL is planned against **policy views**, never raw tables:

- Hidden columns (`expose = false`) and invisible resources do not exist; errors
  are indistinguishable from nonexistent names.
- Masks (`hash` keyed by a Holder salt, `null`, `redact`, `trunc:<unit>`), casts,
  DP clamps, row filters and owner filters are part of the view and are inlined
  into the plan before optimization.
- Aggregates over a `k`-protected resource are rewritten to keep only groups with
  `COUNT(DISTINCT privacy_unit) ≥ k` (or `COUNT(*) ≥ k` without a privacy unit).
  Projecting the privacy unit away before aggregating is rejected (`RMT-E0306`).
- Aggregate-only resources reject any plan in which a scan of them is not under
  an aggregate (`RMT-E0304`).
- `max_rows` is enforced with `LIMIT max_rows + 1` and an error on overflow;
  scans are metered per remit (rows and bytes) and memory is capped by a
  per-remit DataFusion memory pool.

Column lineage (`facts.resources[*].columns`) is computed on the optimized plan
over schema-only views, so filter, join and group keys count as accessed columns,
and is independent of param values.
