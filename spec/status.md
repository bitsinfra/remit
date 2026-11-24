# Status set and leakage accounting

Senders only ever see one of:

| Status | Code (kernel `run` error) | Meaning |
|---|---|---|
| `ok` | — | Typed result released |
| `limit_exceeded` | 1 | Fuel, memory, wall, scan, row cap, call cap, output size |
| `type_violation` | 2 | Output does not inhabit `returns` |
| `denied` | 3 | Policy/authority/budget denial at admission, or a read denied at runtime |
| `internal` | 4 | Kernel exception, syntax error, engine failure |

The status channel carries ⌈log2 5⌉ = **3 bits**, counted in every remit's
`result_bits` and charged even when no value is released (a failure is charged
3 bits; a success is charged `result_bits`; an identical cached answer is
charged 0).

Other channels:

- **Row counts and cap hits** are never returned unless declared in the type; a
  cap hit is `limit_exceeded` (closes the row-count oracle).
- **Errors**: kernel messages stay in Holder logs.
- **Timing**: usage is bucketed (`fuel: "≤20M"`, `wall: "≤50ms"`); resources may
  set `pad_ms` to pad responses to fixed latency classes; there are no clocks in
  the sandbox.
- **Diagnostics/explain**: visible-catalog terms; cost estimates bucketed; `explain`
  can be disabled.
- **Catalog**: scoped per principal; hidden equals nonexistent.
