# Kernel mode

## Contract

```js
export default function main(reads, params) { /* … */ return result; }
```

- `reads.<name>(params?)` calls a declared read template (≤ `max_calls`) and
  returns a lazy, Arrow-backed `Table`: `.length`, `.schema`, `.rows()` (objects;
  timestamps/dates as `Date`), `.col(name)` (`Float64Array` for numbers and epoch-ms
  timestamps, arrays otherwise), and array-like `map/filter/reduce/forEach/some/every/find/slice/at`
  plus iteration. Undeclared reads do not exist.
- Only params the template declares are forwarded, typed by the template
  (`param-type` otherwise).
- `params` timestamps (see manifest.md) arrive as `Date`.
- `holder.call(name, args)` (JS) / `holder(name, args)` (Python) calls a Holder
  function listed in the catalog: pure, priced in fuel, scoped per principal.
- The result is encoded structurally (Dates as CBOR tag 1) and validated by the
  Holder against `returns` ([rt.md](rt.md)).
- `async function main` is allowed; top-level `await` is not.

Languages:

| `lang` | Engine | Contract |
|---|---|---|
| `js/es2023` | `engines/js` (Boa) | `export default function main(reads, params)` (TS is type-checked and stripped by the SDK; only source is sent) |
| `python/monty` | `engines/python` (Pydantic Monty) | `def main(reads, params)`; `reads["busy"](params)` returns a list of dicts; timestamps are RFC 3339 strings |
| `wasm/component` | Sender-built component, restricted engine | the `sender-kernel` world: `run(params) -> result`; `code.source` is the base64 component |

Python and JS engines are Holder-built components of the same `kernel` world.
Sender components are structurally validated (size, functions, code/data bytes,
memories, tables, nested modules, import allowlist), compiled by the Holder with
a restricted engine (no SIMD, GC, memory64, multi-memory, tail calls,
exceptions) under a compile timeout, cached by hash; precompiled artifacts are
never accepted (`RMT-E0604`). Static and dynamic `import` are rejected at admission
(`RMT-E0602`); syntax errors are reported with locations (`RMT-E0601`); a missing
entry export is `RMT-E0603`.

## Determinism

| Ambient | In a kernel |
|---|---|
| `Date.now()` / `new Date()` | `issued_at` (frozen WASI wall clock) |
| `Math.random()` | ChaCha20 stream seeded from `SHA-256("remit:…:" + nonce)` |
| `performance`, timers, `fetch`, `require`, `process`, `WebAssembly`, modules | do not exist |

Same program + params + snapshot + execution context ⇒ same result hash
(replay audits, excluding DP answers). The signed receipt records the clock and
PRNG inputs used for a kernel result, including when that result is cached.

## Engine and world

The Holder hosts the interpreter: a Holder-built component targeting
[`remit:kernel@0.1.0`](wit/kernel.wit). The reference Holder ships `engines/js` — the Boa
interpreter (pure Rust, QuickJS-class) compiled to `wasm32-wasip2` — pinned by
SHA-256 and recorded in receipts (`runtime.engine`). Senders never ship
compiled artifacts. The engine's init-time WASI needs (clocks, random,
environment, stdio) are satisfied by deterministic stubs; sockets and HTTP are not
linked. Three functions exist for Holder-hosted interpreters: `data.declared`
(names of declared reads), `init()` and the `load(source, entry)` export.

**Pre-initialized pool.** Holders keep a pool of instances that already ran
`init()` (engine realm + prelude) before any Sender input exists. A remit takes
one instance, binds its clock (`issued_at`), PRNG (nonce), memory limit and
reads, runs, and the instance is discarded: no instance ever serves two remits.
Instances start from a **Wizer snapshot** of the pinned engine taken after `init()`
(realm and prelude), mapped copy-on-write; if snapshotting fails the Holder falls
back to running `init()` per instance.

### Engine packaging

componentize-qjs and Javy-style providers need a C toolchain with a WASI sysroot
in the Holder's trusted build; Boa builds from Rust alone, reproducibly, so the
reference engine is Boa. Any engine that targets the same world (for example a
QuickJS component) is a drop-in replacement with the same imports and exports;
fuel figures are engine-specific, which is why the catalog publishes the engine
hash and its calibration. Measured numbers are produced by `remit bench` and
recorded in `bench/RESULTS.md`.

**Data handoff.** Reads return `list<u8>` Arrow batches. `stream<u8>` with
`DirectDestination` is not used: it needs component-model-async,
which Holders disable (§isolation) until its fixes settle, and the copy it saves
is ~0.1 ms/MB on tables that are KB-sized after policy.

## Metering

- **Fuel only.** Guest instructions consume fuel; the wall deadline is enforced at
  async fuel yields (every 2M fuel by default); epochs are not used.
- Engine initialization plus loading an empty program is measured at startup
  (`baseline_load_fuel`) and is Holder-paid; parsing and running Sender code,
  including top-level code, is charged.
- Host work is priced (catalog `runtime.fuel_prices`): per call, per row, per
  byte, per Holder-function call. Charges are deducted when control returns to
  the guest; exhausting fuel there traps.
- Fuel is calibrated to time per engine (`remit bench --calibrate`; published in the
  catalog as `runtime.fuel_calibration`).
- A trapped store is never reused: each remit gets a fresh instance from the
  pooling allocator.

Kernel error messages never leave the Holder (they are logged Holder-side; `remit
dev` returns them because its data is synthetic).
