# Receipts

Every terminal state produces a DSSE-signed receipt
(`application/vnd.remit.receipt+json`, JCS payload, Holder key):

```jsonc
{ "run_id": "run_…", "remit_id": "sha256:…", "params_sha256": "sha256:…",
  "sender": "did:web:…", "holder": "did:web:…", "decision": "admitted",
  "policy_sha256": "sha256:…", "catalog_sha256": "sha256:…",
  "data_versions": { "calendar.events": "csv:sha256:…" },
  "result_sha256": "sha256:…", "result_bits_max": 68, "status": "ok",
  "labels": ["no-forward", "personal"], "terms": { "retain_days": 30, "forward": false },
  "usage": { "fuel": "≤20M", "wall": "≤50ms" }, "charged": { "bits": 68, "epsilon": 0 },
  "runtime": { "remit": "0.1.0", "wasmtime": "48.0.10", "engine": "js/es2023@sha256:…", "isolation": "process" },
  "cached": false, "attestation": null, "ts": "2026-11-21T10:00:00.041Z" }
```

- `result_sha256` = SHA-256 of the JCS-encoded normalized result the Sender
  received. SDKs verify the signature and that `remit_id`/`params_sha256` match
  what they sent.
- **Labels and terms are the meet of the inputs**: restriction labels union,
  `retain_days` = minimum, `forward` = all inputs allow (a `no-forward` label
  forbids). SDKs carry them with the value; violations are attributable through
  the signed provenance.
- `data_versions` pin each read to a snapshot (content hash of the source in
  v0.1); with determinism, a replay at the same snapshot must reproduce
  `result_sha256` (DP results excepted).
- Rejections, pending approvals and counter-offers are receipted too.
- Kernel receipts include `execution: { issued_at, nonce }`, which binds the
  frozen clock and PRNG seed to the result. Cached receipts retain the original
  execution context; replay uses it alongside the recorded data versions.
- Senders must check that `result_sha256` matches the JCS form of the result they
  received, that the parties are right, and that the value inhabits the declared
  type. The SDKs do all three.
- **Replay audit**: `remit replay --envelope … --receipt …` re-runs a recorded remit
  at the same data versions and compares `result_sha256` (DP answers excepted).

## Log

Receipts are appended to `receipts.jsonl`: `{seq, prev, hash, envelope}` with
`hash = SHA-256(prev ‖ JCS(envelope))` from a zero genesis. `remit receipts
verify <log.jsonl> --holder-key did:key:…` checks the chain and every signature;
removal, reordering or modification breaks it.

**Transparency.** Every entry is also a leaf of an RFC 6962 Merkle tree
(`leaf = SHA-256(0x00 ‖ JCS(envelope))`). `GET /remit/v1/log/head` returns a
signed tree head (`application/vnd.remit.tree-head+json`: holder, size, root,
ts) and `GET /remit/v1/log/proof/{run_id}` an inclusion proof; a Sender who
keeps tree heads (or gets them from witnesses) can detect a Holder showing
different logs to different Senders.

## Attestation

With `[holder.attestation] format, command`, the receipt embeds
`{"format", "evidence"}`. The evidence binds user data = SHA-256 of the JCS receipt
with `attestation: null`, and nonce = SHA-256(`remit_id|run_id`). AWS Nitro
documents are verified by `remit receipts verify --attestation want.json` (COSE
ES384, chain to the pinned root, freshness, PCRs, binding). Evidence of other TEEs
is carried but never reported as verified. When evidence is `required` and cannot
be produced, no result is released.
