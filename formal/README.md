# Machine-checked lemmas

Each `.smt2` file states a lemma's **negation** and must be `unsat`. Run
`scripts/prove.sh` (needs `z3`). They cover the facts budgets and policy rely on:

| File | Lemma |
|---|---|
| `cap_float.smt2` | quantized floats: at most ⌊(max−min)/p⌋+1 values |
| `cap_time.smt2` | timestamps / dates: at most ⌊(max−min)/g⌋+1 values |
| `cap_list.smt2` | Σᵢ₌₀..ₘ nⁱ ≤ (m+1)·nᵐ, so log2(m+1) + m·cap(T) is sound (lists, strings, bytes, tables) |
| `cap_sum_prod.smt2` | struct and optional counts |
| `cap_monotone.smt2` | capacity never grows when a type is narrowed |
| `ledger.smt2` | reserve/settle keeps 0 ≤ spent ≤ cap, for any interleaving, and a crash only over-charges |
| `zcdp.smt2` | the tighter-of-two privacy bound is monotone in every release |
| `dp_threshold.smt2` | contribution bounding: adding one unit changes ≤ m rows |
| `nonce.smt2` | a nonce is admitted at most once while its envelope is valid |

The programs are tested against the same statements by property tests
(`crates/remit-types/src/tests.rs`, `crates/remit-policy/src/tests.rs`), by
differential testing against the TypeScript oracle, and by the
`capacity_soundness` fuzz target.

# Lean model (`lean/`)

`cd formal/lean && lake build` (Lean 4, no Mathlib). No `sorry`; only Lean's standard
axioms (`lake env lean Axioms.lean`).

| Theorem | Says |
|---|---|
| `normalize_mem` + `length_vals_le` | every value the emit plane can release at a type is one of at most 2^capacity values |
| `normalize_idem` | a released value re-validates to itself |
| `admitted_iff` | a remit is admitted iff every check passed |
| `rejected_frozen` | anything else charges and releases nothing |
| `used_le_cap`, `released_le_cap` | no sequence of requests and settlements overdraws the bit budget |
| `no_replay` | a nonce is admitted at most once, whatever happens in between |

`Oracle.lean` runs the model so Rust can be tested against it: the validator and
capacity (2,000 random types, 20,000 values), the ledger (300 random histories) and
the admission order over HTTP (every single fault, every pair, random sets). Run with
`REMIT_REQUIRE_LEAN=1 cargo test`. Not modelled: string patterns, decimals, bytes,
rolling windows, fuel and privacy budgets, floating-point rounding (the differential
test uses exactly representable numbers).
