# Remit — An agent-to-agent protocol

When agent **A** (the *Sender*) needs an answer from data that agent **B** (the
*Holder*) controls, A sends a **remit**: a small, signed program plus a manifest
declaring what it **reads**, its **limits**, and a **bounded result type**.
B admits it mechanically (analysis → facts → Cedar → budgets), runs it next to
the data in a sandbox with no network, validates the output against the
declared type and returns **only the typed result and a signed receipt**.

```
Sender (LLM + SDK)                         Holder (remit serve)
  pull catalog (signed) ◄──────────────── /.well-known/remit
  write SQL / TS, local check
  sign (DSSE), submit ───────────────────► admission (µs–ms): authn → replay → plan cache →
                                             analyze ⇒ facts → Biscuit → Cedar → budgets
                                           read plane (DataFusion + policy views, k, DP)
                                           compute plane (Wasmtime, fuel, per-trust-domain workers)
  typed result + receipt ◄──────────────── emit plane (validate → quantize/DP → encode) + receipt log
```

Neither side runs an LLM on the other's instructions: the program is the checked
control channel and the typed result is the data channel. Before anything runs,
the Holder computes from the result type the maximum number of bits the answer can
reveal, and charges it against per-principal and global budgets.

This repository contains the [specification](spec/README.md), the reference
Holder and `remit` CLI (Rust), Sender SDKs for TypeScript, Python and Go, an MCP
helper, a Cloudflare Workers edge Holder, runnable examples, benchmarks, fuzz
targets and machine-checked proofs.

## Documentation

Read the [documentation](https://remit.bitsinfra.com/). Start with the [introduction](docs/index.mdx), [installation](docs/installation.md),
and a complete first exchange in [TypeScript](docs/quickstart-typescript.md) or
[Python](docs/quickstart-python.md). Guides cover [agent-to-agent workflows](docs/agent-to-agent.md),
[holders](docs/holders.md), [policies](docs/policies.md) and [receipts](docs/receipts.md).
The searchable Fumadocs site uses the same setup as Fusee and Gnomon; build and
preview instructions are in [CONTRIBUTING.md](CONTRIBUTING.md#documentation).

## Highlights

- **Two modes.** *Query* mode is restricted, fully analyzable SQL run by the
  Holder's engine. *Kernel* mode is sandboxed JS/TS or Python that orchestrates
  declared reads.
- **The result type is the leash.** Every remit declares a bounded type (Remit
  Types); its capacity in bits is computed before execution and charged to
  budgets.
- **Policy decides on facts.** The analyzer derives facts (columns, operations,
  aggregate-only, k, bits, cost); [Cedar](https://www.cedarpolicy.com/) decides;
  delegated authority travels as [Biscuit](https://www.biscuitsec.org/) tokens.
- **Privacy in trusted code.** k-thresholds, masks, contribution bounding and
  differential-privacy noise run in the Holder, never in Sender code.
- **Hard sandbox.** Wasmtime components with zero ambient imports, fuel-only
  deterministic metering, and per-trust-domain worker processes (macOS sandbox;
  Linux namespaces, Landlock and seccomp; optional microVMs).
- **Receipts.** Every terminal state is receipted; receipts are DSSE-signed,
  hash-chained and covered by RFC 6962 Merkle tree heads, and `remit replay`
  audits determinism.
- **Rides existing rails.** Native HTTP API, Connect/gRPC, MCP and A2A bindings;
  RFC 9421 HTTP signatures, `did:key`, `did:web`.

## Install

| Component | Install |
|---|---|
| `remit` CLI and Holder | `cargo install bitsinfra-remit`, or a signed prebuilt binary from [Releases](https://github.com/bitsinfra/remit/releases) |
| TypeScript SDK, `remit-mcp`, `remit-ts` | `npm install remit-protocol` |
| Python SDK | `pip install remit` (add `remit[native]` for the Rust verifier core) |
| Go SDK | `go get github.com/bitsinfra/remit/sdk/go` |
| Rust crates | [`remit-holder`](crates/remit-holder) to embed a Holder; [`remit-types`](crates/remit-types), [`remit-wire`](crates/remit-wire) and friends for the pieces |

A Holder also needs its kernel engine components (`remit_engine_js.wasm`, and
optionally `remit_engine_python.wasm`). Releases ship them next to the binaries;
from a checkout, build them with `scripts/build-engine.sh`.

## Getting started

Prerequisites: Rust 1.98+ via rustup (with the `wasm32-wasip2` and
`wasm32-unknown-unknown` targets; `rust-toolchain.toml` selects them), Node.js
≥ 22.18 for the TypeScript examples, Python 3 to regenerate example data.

```bash
scripts/build-engine.sh          # engines/{js,python} → engines/*/dist/*.wasm, prints their sha256
```

```bash
cargo build --release -p bitsinfra-remit
```

```bash
scripts/build-verifier.sh        # optional: the Rust verifier as Wasm for the TS SDK (needs wasm-bindgen-cli)
```

Start Alice's personal vault, then ask it for free slots from a second terminal:

```bash
cd examples/personal-vault && ../../target/release/remit serve
```

```bash
cd examples/personal-vault && REMIT_IDENTITY=keys/travel-agent.json node demo.ts
```

Or use the CLI:

```bash
cd examples/personal-vault && ../../target/release/remit run remits/free-slots.example.json --holder http://127.0.0.1:8443 --identity keys/travel-agent.json
```

The result is three slots (≈ 64 bits of capacity), never titles, attendees or
locations, and the response carries a signed receipt. See
[examples/](examples/README.md) for the other Holders (enterprise analytics with
DP, a B2B clean-room overlap, retrieval over documents, a multi-Holder graph).

## Sender SDKs

TypeScript ([`sdk/ts`](sdk/ts/README.md)):

```ts
import { Remit } from "remit-protocol";
import { z } from "zod";

const remit = new Remit({ identity: await Remit.identity.fromEnv() });
const crm = await remit.holder("http://127.0.0.1:8444");

const arr = await crm.query({
  sql: `SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region`,
  returns: z.array(z.object({ region: z.enum(crm.enums("crm.accounts.region")), arr: z.number().min(0).max(1e10).multipleOf(1000) })).max(20),
});
arr.value;   // typed values; strings come back as Untrusted
arr.receipt; // verified receipt (labels, terms, data versions, result hash)
```

Python ([`sdk/python`](sdk/python/README.md)) and Go ([`sdk/go`](sdk/go/README.md))
offer the same model. [`sdk/skill/SKILL.md`](sdk/skill/SKILL.md) is an authoring
guide for agents that write remits, and `remit-mcp` (in the TypeScript package)
exposes a Holder to any MCP client.

## Repository layout

```
spec/                normative spec, JSON Schemas, WIT world, protobuf, conformance vectors
crates/
  remit-types/       Remit Types (RT): capacity calculator, validator, JSON Schema profile
  remit-wire/        manifest, JCS (RFC 8785), DSSE, did:key identities, remit_id, RFC 9421, JWT
  remit-sql/         Remit SQL dialect profile (sqlparser-rs)
  remit-analyze/     facts: columns, ops, aggregate-only, k, bits, cost; diagnostics; JS early errors (oxc)
  remit-policy/      Cedar schema/engine, presets, lint/diff, Biscuit authority, budget ledgers (WAL)
  remit-read/        DataFusion read plane: policy views, masks, row/owner filters, k-thresholds, DP, caps,
                     snapshots, full-text/kNN search; CSV, Parquet, NDJSON, SQLite, Postgres, Delta, Iceberg,
                     optional DuckDB, MySQL, Lance, object stores
  remit-kernel/      Wasmtime host: pre-initialized pool, fuel + priced host I/O, deterministic WASI stubs,
                     sandboxed worker processes, microVM isolation, Sender-built components
  remit-emit/        validation, trusted transforms, DP noise (OpenDP), encoding
  remit-receipt/     receipts, label meet, hash-chained log, RFC 6962 Merkle tree heads, TEE evidence
  remit-holder/      admission pipeline, HTTP API, Connect (remit.v1), MCP + A2A bindings, approvals, catalog
  remit-cli/         the `remit` binary (published as `bitsinfra-remit`)
  remit-guest/       PID 1 of a kernel microVM
  remit-verify-wasm/ the verifier compiled to Wasm for SDKs (+ conformance tests)
  remit-py/          PyO3 bindings (`remit_native`, built with maturin)
engines/js/          Holder-built JS engine component (Boa → wasm32-wasip2, remit:kernel world)
engines/python/      Holder-built Python engine component (Monty → wasm32-wasip2)
sdk/ts/              TypeScript SDK, remit-mcp, remit-ts
sdk/python/          Python SDK
sdk/go/              Go SDK
sdk/skill/           authoring skill for agents
backends/cloudflare/ edge Holder on Cloudflare Workers (D1 + Dynamic Workers)
formal/              SMT lemmas and a Lean 4 model of capacity, admission and budgets
bench/               criterion + callgrind benchmarks, RemitBench (208 tasks, adversarial track)
fuzz/                cargo-fuzz targets and an OSS-Fuzz project
examples/            personal-vault, enterprise-analytics, b2b-overlap, docs-rag, graph-demo.ts
```

## Testing

```bash
cargo test --workspace           # unit, property, conformance, process isolation, adversarial
```

```bash
cd sdk/ts && npm ci && npm test  # TS oracle, differential tests against the Wasm verifier
```

```bash
scripts/conformance.sh           # black-box suite against the example Holders
```

```bash
scripts/prove.sh                 # SMT lemmas (needs z3)
```

```bash
node bench/remitbench/run.ts --spawn --quiet
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists every check CI runs and how to run it locally.
Benchmark numbers are in [bench/RESULTS.md](bench/RESULTS.md).

## Status and security

The specification is at **0.1** and the wire version is `0.1`
([versioning](spec/VERSIONING.md)). Remit has not yet had an independent security
audit; read the [threat model](spec/threat-model.md) and [SECURITY.md](SECURITY.md)
before putting a Holder in front of sensitive data, and report vulnerabilities
privately as described there.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
