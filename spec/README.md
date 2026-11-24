# Remit specification 0.1

Research preview: the specification and wire version are `0.1` (see
[VERSIONING.md](VERSIONING.md)).

Normative documents for the Remit protocol. The Rust crates are the
reference implementation; `sdk/ts` is an independent implementation of the
canonicalization and capacity rules used as a test oracle (Python and Go are two
more); differential tests require all of them to accept and reject the same types.

| Document | Covers |
|---|---|
| [manifest.md](manifest.md) | The remit: envelope (DSSE), manifest fields, `remit_id`, params, limits, templates |
| [rt.md](rt.md) | Remit Types: syntax, bounds, capacity in bits, validation, trusted transforms, JSON Schema profile |
| [sql.md](sql.md) | The Remit SQL dialect profile |
| [kernel.md](kernel.md) | Kernel mode: the `remit:kernel` WIT world ([wit/kernel.wit](wit/kernel.wit)), the JS contract, determinism |
| [admission.md](admission.md) | The admission pipeline, facts, Cedar schema, outcomes, diagnostics |
| [status.md](status.md) | The fixed status set and leakage accounting |
| [diagnostics.md](diagnostics.md) | Every diagnostic code and what it means |
| [catalog.md](catalog.md) | `/.well-known/remit`: resources, hints, runtime, examples, stats profiles, signing |
| [receipts.md](receipts.md) | Receipts, labels/terms (meet), the hash-chained log, replay audits |
| [protocol.md](protocol.md) | HTTP API, MCP extension `io.github.bitsinfra/remit`, A2A extension |
| [isolation.md](isolation.md) | Isolation levels, the worker process model, hygiene |
| [threat-model.md](threat-model.md) | Threat model v1 and leakage channels |

Machine-readable artifacts:

- `schema/manifest.schema.json`, `schema/rt.schema.json`, `schema/receipt.schema.json`: JSON Schemas (2020-12).
- `wit/kernel.wit`: the kernel world.
- `conformance/`: vectors and the black-box Holder suite ([README](conformance/README.md)).
- `proto/remit/v1/remit.proto`: the RPC surface.
- `conformance/*.json`: vectors all implementations must pass (`cargo test -p remit-verify-wasm --test conformance`, `npm test` in `sdk/ts`).

Diagnostic codes are stable: `RMT-E01xx` types, `E02xx` SQL, `E03xx` read
plane, `E04xx` runtime limits, `E05xx` internal, `E06xx` kernel source,
`E00xx` envelope/auth/freshness, `E005x` policy, `E006x` budgets,
`E016x` differential privacy. Warnings are `RMT-Wxxxx`.
