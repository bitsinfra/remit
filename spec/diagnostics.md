# Diagnostics

Every diagnostic carries a stable `code`, a JSON-pointer `path`, a `message`, and
when known a `span` (in SQL or kernel source), a `hint`, a machine-applicable
`fix` (RFC 6902 JSON Patch) and a `docs` link to the entry below. Codes are never
reused ([VERSIONING.md](VERSIONING.md)); messages and hints may improve. Errors are
`RMT-Exxxx`; warnings, which never block admission, are `RMT-Wxxxx`.

## Envelope, authentication and freshness

### RMT-E0001
The envelope is larger than the Holder accepts.

### RMT-E0002
The request body is not a DSSE envelope.

### RMT-E0003
The envelope or manifest is malformed: wrong payload type, a non-canonical payload
(it must be JCS, see [manifest.md](manifest.md)), an unsupported `remit` version,
or an invalid field (for example a short nonce or a prose purpose).

### RMT-E0010
No valid signature from a key of `manifest.sender`, or the signer is not the sender.

### RMT-E0011
The HTTP message signature (RFC 9421) was made by a different identity than the
envelope's sender.

### RMT-E0012
The request's transport authentication (HTTP message signature, WIMSE token) is
missing or invalid.

### RMT-E0020
The remit is addressed to a different Holder (`manifest.holder`).

### RMT-E0021
The remit has expired; re-sign it with a fresh `expires_at`.

### RMT-E0022
`issued_at` is in the future beyond the allowed clock skew.

### RMT-E0023
The validity window (`expires_at − issued_at`) is longer than the Holder allows.

### RMT-E0024
The nonce was already used: replays are refused.

### RMT-E0030
`code.source` is absent and no blob with `code.source_sha256` exists. Upload it with
`PUT /remit/v1/blobs/{sha256}` or inline the source.

## Authority, policy and budgets

### RMT-E0040
The remit carries delegated authority tokens, but this Holder does not accept them.

### RMT-E0041
A Biscuit authority token does not verify or does not authorize this remit.

### RMT-E0042
An OAuth transaction token does not verify or does not match this remit.

### RMT-E0050
Denied by policy: an action on a resource is not permitted for these facts. Compare
the remit against the catalog's `policy_hints` ([admission.md](admission.md)).

### RMT-E0060
A budget (bits, ε or fuel; per principal or global) cannot cover this remit.
Budgets refill over their window; a tighter result type spends fewer bits.

## Result types, params and limits

### RMT-E0101
A type has no bound. Add `max`, `max_len`, `min`/`max` or `granularity` ([rt.md](rt.md)).

### RMT-E0102
Unknown or malformed type: a type is a string (`"bool"`) or an object with exactly
one key naming the type.

### RMT-E0103
A bound is invalid (not a number, not finite, or out of range for the type).

### RMT-E0104
A bound refers to a `$param` that is not bound.

### RMT-E0105
Empty range: `min > max`.

### RMT-E0106
A size is too large (lists, strings, tables or enums above the profile's maximums).

### RMT-E0107
Invalid granularity: it must be a positive duration such as `"15m"`, and whole days
for dates.

### RMT-E0110
The SQL uses a `$param` that the read template does not declare.

### RMT-E0111
A param is referenced (by `returns` or a template) but missing from `params`.
Templates without params can be checked but not run.

### RMT-E0120
The result type does not match the query's output columns: alias columns to the
struct's field names, or return one column for a scalar.

### RMT-E0130
The result type's capacity is unbounded, or above the manifest's own `limits.bits`.

### RMT-E0140
A limit (`max_rows`, `max_calls`, fuel, memory, wall, output) exceeds the Holder's
ceiling. Usually returned with a counter-offer whose `fix` lowers it.

### RMT-E0150
The mode (`query` or `kernel`) is not offered by this Holder.

### RMT-E0151
No engine for the kernel's `code.lang` on this Holder; the message lists the
available languages.

### RMT-E0160
The remit reads a DP-governed resource but declares no `limits.epsilon`.

### RMT-E0161
The differential-privacy rewrite cannot bound this plan's sensitivity (for example
an unbounded sum, an unsupported aggregate, or a filter on the noisy result). Use
`COUNT`/`SUM`/`AVG` with `GROUP BY` over bounded columns.

### RMT-E0162
`limits.epsilon` exceeds the per-remit maximum.

### RMT-E0163
`limits.delta` is outside `(0, max]`.

## Remit SQL

### RMT-E0201
The SQL does not parse.

### RMT-E0202
Not a single `SELECT` query (DDL, DML, utility statements or several statements).

### RMT-E0203
`WITH RECURSIVE` is not allowed.

### RMT-E0204
Set operations (`UNION`, `INTERSECT`, `EXCEPT`) are not allowed.

### RMT-E0205
A function is not allowed: clocks (`now()`, `current_*`), randomness, UDFs and
qualified functions. Pass time as params (`$from`, `$until`).

### RMT-E0206
The join type is not allowed (only inner and left joins).

### RMT-E0207
A clause is not in the profile (locking, `SELECT INTO`, dialect-specific clauses).

### RMT-E0208
Positional params (`$1`) are not allowed; use named params.

### RMT-E0209
A relation must be named `source.table`.

### RMT-E0210
The SQL text or its nesting is too large.

### RMT-E0211
A search function's (`fts`, `knn`) first argument must be a string literal naming
an index.

### RMT-E0212
Unknown relation (from the offline binder in the SDKs).

### RMT-E0213
Unknown column (from the offline binder in the SDKs).

See [sql.md](sql.md).

## Read plane

### RMT-E0300
The read plane rejected the resource's configuration.

### RMT-E0301
The query does not plan against the catalog: an unknown or invisible relation or
column. Hidden resources and columns are indistinguishable from nonexistent ones.

### RMT-E0304
An aggregate-only resource is read without aggregating, or searched.

### RMT-E0305
A param is undeclared in its read template, missing, or not a valid value of its
declared type.

### RMT-E0306
The privacy unit (the column that identifies whose data a row is) is projected away
where k-thresholds or differential privacy need it.

## Runtime

### RMT-E0400
A runtime limit was hit (rows, scan bytes, memory, time). Reported to the Sender as
status `limit_exceeded`.

### RMT-E0500
Internal error. Details stay in Holder logs.

## Kernel source

### RMT-E0601
Syntax error in the kernel source; the span locates it.

### RMT-E0602
Static or dynamic `import`: kernels have no modules beyond their reads.

### RMT-E0603
The entry export (`main` by default) is missing.

### RMT-E0604
A Sender-built component (`lang = "wasm/component"`) is malformed or does not
target the `sender-kernel` world; precompiled artifacts are never accepted.

### RMT-E0610
TypeScript type error in a kernel (reported by the TypeScript SDK's local check).

See [kernel.md](kernel.md).

## Warnings

### RMT-W0101
An unquantized float carries 64 bits; add `precision`.

### RMT-W0102
The worst-case encoded result is larger than `limits.output_bytes`, so a large
result would be rejected.

### RMT-W0201
The result type can carry more bits than a resource allows per remit (SDK local
check against the catalog).

### RMT-W0202
The purpose is not one the resource serves (SDK local check); the `fix` picks one.

### RMT-W0203
At its read caps, the kernel may need more fuel than `limits.fuel` (SDK local
estimate).
