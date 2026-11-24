# Admission

Admission is mechanical: nothing on the path reads Sender-authored natural
language. Steps (timed in the `trace` of `/check` responses):

| Step | What | Failure |
|---|---|---|
| decode | Size caps, DSSE JSON | `RMT-E0001/2` |
| authn | Transport signature if present (RFC 9421, WIMSE), DSSE signature, canonical payload, key ↔ sender. The key resolver is authoritative | `RMT-E0003`, `RMT-E0010/11/12` (denied) |
| freshness | holder id, expiry, skew, validity window, nonce replay (`/run` only) | `RMT-E0020..24` |
| plan_cache | key `remit_id × catalog_sha × policy_sha × scope × params_sha` | — |
| analyze | Types/capacity, SQL profile, lineage over the principal's views, JS early errors, limits & clamps, DP plan | diagnostics |
| authority | Biscuit tokens: every requested (resource, action) needs a `right`; all checks pass. OAuth transaction tokens (`txn:<jwt>`): audience, workload, purpose, resources, bits | `RMT-E0040/41/42` (denied) |
| decide | Cedar `is_authorized` per (principal, action, resource) with facts as context | `RMT-E0050` (denied) |
| approvals | Resource `approval = required \| first-use` without a standing approval | `pending_approval` |
| counter-offer | Limits above Holder ceilings | `counter_offer` (JSON Patch) |
| reserve | Bits, fuel, privacy loss, concurrency on per-principal and global ledgers (rolling windows, durable before anything runs) | `RMT-E0060`; `429` + `Retry-After` when busy (the envelope may be retried) |

## Facts (Cedar context)

```cedarschema
type Facts = {
  "mode": String, "purpose": String,
  "columns": Set<String>,          // columns of *this* resource touched by any read
  "ops": Set<String>,              // join, left_join, group_by, having, order_by, limit, window, distinct, subquery, cte, aggregate, collect, kernel
  "aggregate_only": Bool,          // every scan of this resource is under an aggregate (no string_agg/array_agg)
  "min_group_size": Long,          // k enforced in the plan (0 if none)
  "result_bits": Long,             // ⌈capacity⌉ + status bits
  "fuel": Long, "memory_bytes": Long, "wall_ms": Long,
  "max_rows_total": Long,          // Σ max_rows × max_calls over reads of this resource
  "epsilon_milli": Long,
  "standing_approval": Bool,
  "authority": Set<String>,        // issuers of verified delegated authority: "biscuit:ed25519/…", "txn:<iss>"
};
```

Entities: `Remit::Agent` (attrs `org`, `verified`, `tags`; parents
`Remit::Group`), `Remit::Table` (attrs `labels`, `sensitivity`, `purposes`,
`operations`, `max_bits`, `aggregate_only`, `k`, `dp`, `owner_scoped`; parent
`Remit::Dataset` = source name). Actions: `read`, `aggregate` ∈ `read`, `search`
∈ `read`, `call`, `run_kernel`. Requested actions per resource: `aggregate` if
the resource's reads are aggregate-only, else `read`; plus `run_kernel` in kernel
mode. **All** requests must be allowed. Full schema: `remit_policy::SCHEMA`.

Base policies (always on): forbid non-aggregate access to aggregate-only
resources, operations not offered, `result_bits > resource.max_bits`, and
purposes outside a resource's vocabulary. Presets: `personal-vault`,
`aggregate-only`, `dp-analytics`, `owner-rows-only`, `internal-trusted`.

## Outcomes

| Decision | HTTP (`/run`) | Body |
|---|---|---|
| `admitted` → run | 200 | result, labels, terms, provenance, receipt, bucketed usage |
| `rejected` | 422 (invalid) / 403 (denied) | `diagnostics[]` + a signed receipt |
| `pending_approval` | 202 | `ticket`, `access_card` |
| `counter_offer` | 409 | `counter_offer.json_patch`, diagnostics with `fix` |
| `busy` | 429 + `Retry-After` | |

`/check` always answers 200 with the decision in the body and never consumes a
nonce or reserves budget.

## Diagnostics

```json
{ "code": "RMT-E0205", "path": "/reads/busy/sql", "span": [1, 52],
  "message": "function `now` is not in the Remit SQL allowlist",
  "hint": "time always comes from params: compare against `$from`/`$until` instead",
  "docs": "https://github.com/bitsinfra/remit/blob/main/spec/diagnostics.md#rmt-e0205",
  "fix": [{"op": "add", "path": "/reads/busy/params/from", "value": "timestamp"}] }
```

Messages are phrased in visible-catalog terms only. `fix` is an RFC 6902 patch
when the repair is mechanical.

## Standing approvals and access cards

An approval binds `(remit_id, principal constraint, param constraint, expiry)`.
Principal constraints: exact id, `group:<name>`, `*`. Param constraints:
`max_span = {from, until, max}` and per-param `{eq, in, min, max, max_len}`.
Because approval binds to the hash, any code change resets it. Approvers (and
reviewer agents) see only the analyzer-rendered **access card**: reads,
resources, columns, aggregated flags, output type, result bits, limits, purpose.

## Budgets

- **Rolling** windows: 1 minute (1 s slots) and 1 day (15 min slots). A slot
  expires only when all of it is older than the window.
- Reserve before running, settle after. The reservation is written to the WAL
  first (fail closed); one that never settled stays charged in full.
- Privacy loss is kept as pure ε and as zCDP ρ; a cap is compared with the
  tighter sound bound: Σε (nothing Gaussian released) or ρ + 2√(ρ ln 1/δ).
  Optional per-dataset lifetime caps never reset.
- Cached answers (same program, params, data versions, policy) are free for a
  principal that already received them, cost a *new* principal its own bits and
  ε, and never charge the global ledgers again.
- Principals without a verified group share `unverified_global_share` of every
  global budget, so Sybils cannot starve verified agents.
- Execution slots are scheduled by weighted fair queuing per principal with
  bounded queues.

## Differential privacy

A read over a DP-governed resource must be `[LIMIT] [ORDER BY] SELECT keys,
aggregates FROM rows [GROUP BY keys]` where `rows` is row-level (filters,
projections, derived tables, joins on the privacy unit or to non-DP tables) and
built from *total* expressions (nothing that can fail on data). `HAVING`, windows,
`DISTINCT`, nested aggregates and subqueries are refused (`RMT-E0161`).
Aggregates: `COUNT`, `COUNT(DISTINCT unit)`, `SUM`, `AVG` over expressions whose
bounds follow from declared column bounds.

The plan is rewritten to keep at most `max_contributions` rows per privacy unit,
clamp summed values, and count units per group. Noise (OpenDP Laplace or
Gaussian) is added to every quantity with an equal share of ε; group keys are
released only above a τ-threshold (δ per remit, and at least `k`). Ordering and
limits apply to the noisy answer; results are clamped to the declared type.
Kernels may read DP-governed resources: they only ever see noisy answers, and ε is
split over the declared `max_calls`.
