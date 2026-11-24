# Remit on Cloudflare Workers (edge Holder)

An alternative Holder backend: D1 is the read plane, kernels run in **Dynamic
Workers** created per program hash with `globalOutbound: null` and an empty
environment, and the same Rust verifier (as Wasm) does canonicalization, the SQL
profile, binding, capacity and result validation.

It serves the native API (`/.well-known/remit`, `/remit/v1/check`, `/run`,
`/receipts/{id}`), accepts the same envelopes and returns the same receipts, so
every Sender SDK works against it unchanged.

## What is different from the reference Holder ("edge profile")

| | Reference Holder | Edge profile |
|---|---|---|
| Read plane | DataFusion + policy views | D1 (SQLite) over Holder-written views; Remit SQL is bound to the catalog and rewritten to those views |
| Policy | Cedar | declared per resource (purposes, columns, `max_bits`, `aggregate_only`, groups) |
| k-thresholds / DP | yes | not offered: resources needing them must use the reference Holder |
| Kernel reads | data-dependent, `max_calls` | each read runs once, with the remit's own params |
| Metering | fuel | CPU ms (Dynamic Worker `limits`), wall clock; **not deterministic fuel** |
| Isolation | Wasm in a per-trust-domain process | V8 isolate per program hash, no outbound network, no bindings |
| `rows` order | engine order | engine order; use ORDER BY for stable hashes |

Receipts say `isolation: "cloudflare-dynamic-worker"`, so a Sender can refuse it.
