# Threat model v1

| Adversary | Goals | Defenses in this implementation | Known gaps |
|---|---|---|---|
| Malicious Sender | Sandbox escape, DoS, exfiltration beyond the grant | Wasm sandbox with zero ambient imports; per-trust-domain worker processes; fuel/memory/wall/output caps; scan caps; Sender code is only interpreted; bounded result types validated after execution; budgets; optional microVM isolation (one KVM guest per trust domain) | `process` isolation relies on the host kernel's sandboxing; `microvm` needs Linux with KVM |
| Malicious Sender, many remits | Differencing, averaging, reconstruction | Per-principal and global per-dataset bit budgets; global ε ledger; identical (remit, params, snapshot) answers served from cache at zero cost (defeats averaging of DP noise); k-thresholds in the plan; targeting a single unit through a filter yields an empty result | A DP answer lost from the result cache (restart, eviction) is a new, charged release |
| Sybil Senders | Multiply per-principal budgets / exhaust global budgets | Global ledgers; verified groups required by presets; concurrency caps | Unverified principals share a capped slice of global budgets |
| Transient-execution attacker | Read beyond the grant via Spectre | Workers hold only already-granted, post-policy data per trust domain; no clocks or threads in the sandbox | |
| Malicious Holder | Fabricate results; inject instructions into the Sender | Signed receipts with result hashes and data versions; hash-chained log; typed results; `Untrusted<string>` in SDKs; enum values are Holder-declared | Witness network for tree heads is deployment work |
| Network | Tamper, replay | TLS (deployment), DSSE signatures over canonical payloads, nonce + expiry, holder binding | TLS termination is the deployment's |
| Confused deputy | Sub-agent misuses delegated authority | Biscuit attenuation (checks only narrow), purpose binding, short expiry | |

## Leakage channels

See [status.md](status.md). Result value: type capacity, validated after
execution, DP for governed data. Status: 3 bits, always charged. Row counts and
cap hits: never returned. Timing: bucketed usage, optional padding classes.
Diagnostics: visible-catalog terms only. Catalog: per-principal scope.

## Adversarial test list (implemented as tests)

- Escape attempts: no `fetch`/`require`/`process`/`WebAssembly`/timers; imports rejected.
- Fuel evasion: infinite loops in `main` and at top level; host-work pricing.
- Memory-growth storms: capped by the store limiter.
- Wall-clock: busy loops with unlimited fuel stop at the deadline.
- Row/call caps; undeclared reads; hidden columns/resources indistinguishable from nonexistent.
- k-threshold differencing: single-unit targeting returns nothing; projecting the privacy unit away is rejected.
- Aggregate-only bypass via raw scans, `string_agg`/`array_agg`.
- Replay (nonce reuse), expiry, wrong holder, wrong signer, non-canonical payloads.
- Budget exhaustion per principal and globally (Sybil), WAL replay.
- Receipt log tampering (removal/modification).
- Unregistered `did:key` when refused; stolen transport signatures; forged JWTs; SSRF through `did:web`.
- Table-function parameter injection; search as an oracle over hidden rows; search over aggregate-only resources.
- DP: exact HAVING/k, unbounded joins and sums, spoofed privacy units, data-dependent errors, averaging, syntactic variants, outlier contributors.
- Capacity overflow (timestamp ranges), differential accept/reject of mutated types across four implementations.
- Cached answers to new principals; client disconnects; crash between reserve and settle; nonce replay across restarts; blob and queue flooding.
- Process isolation: OS escape self-test, compile bombs, regex/recursion/promise/BigInt/memory storms, cyclic and deep results, Spectre gadgets without clocks, one process per trust domain.
- RemitBench adversarial track: injection exposure and exfiltration beyond capacity are both 0.
