# Catalog (`GET /.well-known/remit`)

A JSON document, content-addressed (`catalog_sha256` = SHA-256 of the JCS form
without that field) and signed with a detached DSSE signature:

```
Remit-Signature: keyid="did:web:alice.vault.example#z6Mk…", sig="<base64 Ed25519 over PAE(application/vnd.remit.catalog+json, JCS(document))>"
ETag: "sha256:…"
```

Fields:

- `holder`, `keys[]` (`kid`, `did_key`, `alg`), `remit` (version).
- `resources[]`: `name`, `kind`, `description`, `columns[]` (`name`, `type` ∈
  bool/int/float/timestamp/date/string/bytes, `nullable`, optional `enum`,
  `masked`, `bounds`), `labels`, `sensitivity`, `rows` (bucket), `hints`
  (`operations`, `aggregate_only`, `k`, `privacy_unit`, `max_bits_per_remit`,
  `purposes`, `dp`, `approval`, `owner_rows_only`), `terms`.
- `policy_hints[]`: one line per resource, e.g.
  ``"`calendar.events`: columns {start_at, end_at, status}; ≤128 bits/remit; purpose ∈ {scheduling}"``.
- `purposes[]`: the purpose vocabulary.
- `runtime`: `modes`, `languages`, `limits` (ceilings and defaults),
  `fuel_prices`, `engine` (`lang`, `engine`, `sha256`), `wasmtime`, `isolation`,
  `status_set`, `status_bits`.
- `indexes[]`: search indexes visible to the principal (`name`, `kind`
  fulltext|vector, `table`, `id_column`, `function` signature).
- `runtime.functions[]`: Holder functions the principal may call (`name`,
  `description`, `fuel`); `runtime.fuel_calibration`: measured ns per fuel.
- `examples[]` and `purposes[]` are scoped like resources.
- `examples[]`: Holder-authored example remits (`title`, `manifest`).
- `stats`: optional DP-noised profiles per resource (bucketed row count; per
  column: null rate, histogram over data-independent buckets, year histogram for
  times, length/distinct buckets for strings), computed once with
  `[catalog.profiles] epsilon`.

**Scoping.** Without credentials the public scope is served (resources with
empty `visible_to`). A Sender may present `Remit-Proof: <base64 DSSE envelope>`
(payloadType `application/vnd.remit.catalog-request+json`, payload
`{holder, principal, ts}`, ts within 5 minutes) to receive its scoped catalog.
Hidden resources are indistinguishable from nonexistent ones.

Codegen: `remit pull <holder>` writes `.remit/<name>/{catalog.json, types.d.ts,
schema.sql, stats.json, examples/}` — the LLM's compact API reference.
