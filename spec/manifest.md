# The remit manifest (v0.1)

## Envelope

A remit is submitted as a **DSSE envelope**:

```json
{ "payloadType": "application/vnd.remit.manifest+json",
  "payload": "<base64 of the JCS-canonical manifest>",
  "signatures": [{ "keyid": "did:web:travel-agent.example#z6Mk…", "sig": "<base64 Ed25519 over PAE>" }] }
```

- `PAE = "DSSEv1" SP len(type) SP type SP len(body) SP body` (DSSE v1).
- The payload MUST be RFC 8785 (JCS) canonical. Holders re-canonicalize and
  reject non-canonical payloads (`RMT-E0003`), so every party hashes the same bytes.
- Ed25519 is required. `keyid` is either a `did:key` (self-certifying) or
  `<did>#<multibase key>` for an id registered with the Holder
  (`[[principal]] keys = ["did:key:…"]`). The signing key MUST belong to
  `manifest.sender` (`RMT-E0010`).
- Size caps: manifest ≤ 64 KiB plus inline code ≤ 256 KiB; envelope ≤ 512 KiB.

## Fields

| Field | Type | Notes |
|---|---|---|
| `remit` | `"0.1"` | Protocol version |
| `sender`, `holder` | DID | `holder` MUST equal the receiving Holder's id (`RMT-E0020`) |
| `issued_at`, `expires_at` | RFC 3339 | `expires_at > now`, `issued_at ≤ now + skew`, window ≤ Holder max (default 900 s) |
| `nonce` | 8–128 chars | Replay protection (per sender, until expiry); seeds the kernel PRNG |
| `purpose` | string | From the Holder's purpose vocabulary (catalog `purposes`) |
| `authority` | string[] | Optional Biscuit tokens (`biscuit:<base64>`) |
| `mode` | `query` \| `kernel` | |
| `reads` | map name → template | Identifiers; ≥ 1 |
| `code` | object | Kernel mode only: `{lang, entry, source_sha256, source?}` |
| `params` | object | Absent ⇒ the manifest is a **template** (checkable, not runnable) |
| `limits` | object | See below |
| `returns` | RT JSON or JSON Schema | See [rt.md](rt.md) |

Unknown fields are rejected.

### Read templates

```json
"busy": { "sql": "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from",
          "params": { "from": "timestamp", "until": "timestamp" }, "max_rows": 500, "max_calls": 1 }
```

- `params` types: `timestamp | date | int | float | string | bool`. Every `$name`
  in the SQL MUST be declared (`RMT-E0110`).
- `max_rows` (≥ 1) caps each call; exceeding it is `limit_exceeded`, never truncation.
- `max_calls` (default 1) caps calls from a kernel. Query mode requires exactly one
  root read with `max_calls = 1`.
- Total readable rows are bounded by `Σ max_rows × max_calls`; policy sees the bound
  (`max_rows_total`).

### Top-level params

`params` binds read-template params by name (query mode) and is passed to the
kernel's `main(reads, params)`. A top-level param whose name is declared as a
`timestamp` in any read template is delivered to kernels as a `Date`.
`returns` bounds may reference params (`"$from"`).

### Limits

| Limit | Default (reference Holder) | Notes |
|---|---|---|
| `fuel` | 50M | Deterministic instruction budget and billing unit |
| `memory_bytes` | 32 MiB | Guest linear memory; also the read-plane memory pool |
| `wall_ms` | 1000 | Safety net, enforced at fuel yields |
| `scan_rows`, `scan_bytes` | Holder max | Read-plane caps across all reads/calls |
| `output_bytes` | 64 KiB | Cap on the encoded (JCS) result |
| `epsilon`, `delta` | — | DP budget (required for DP-governed resources) |
| `bits` | — | Sender pre-commitment: capacity above it is rejected (`RMT-E0130`) |

Limits above the Holder's ceilings produce a **counter-offer** (`409`, JSON Patch);
the Sender re-signs the patched manifest and resubmits.

## Identity hashes

```
remit_id      = "sha256:" + hex(SHA-256(JCS({remit, mode, purpose, reads, code', limits, returns})))
params_sha256 = "sha256:" + hex(SHA-256(JCS(params ∪ {})))
```

`code'` is `code` without `source`, with `source_sha256` lowercased and without a
`sha256:` prefix (inline and blob-uploaded code have the same id). `reads` is
serialized with `max_calls` always present and `params` omitted when empty;
`limits` omits absent fields. `remit_id` excludes sender, holder, authority,
params, nonce and timestamps, so "same program, new params" hits plan and
approval caches. Vectors: `conformance/remit_id.json`.

## Code blobs

Large code is uploaded once: `PUT /remit/v1/blobs/{sha256}` with the UTF-8 source
as the body; the manifest then omits `code.source`. **The Holder never fetches
URLs on the Sender's behalf.**

`purpose` is a vocabulary token (`[A-Za-z0-9_.:-]{1,64}`), never prose: it reaches policy, access cards and logs.
`authority[]` holds Biscuits (`biscuit:…`) and OAuth transaction tokens (`txn:<jwt>`).
