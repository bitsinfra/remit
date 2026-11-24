# Benchmark results

## Performance targets — `remit bench`

Reproduce with `remit bench --json` (release build, `scripts/build-engine.sh js`
first). The targets are for one commodity x86-64 core; the numbers below were
taken on Apple Silicon (aarch64, macOS, 18 cores), release build, in-process
isolation, on a **shared host** (load average ~30 from other processes), over three
consecutive runs.

| Path | p50 (runs 1 / 2 / 3) | p99 (runs 1 / 2 / 3) | Target p50 / p99 | Status |
|---|---|---|---|---|
| Admission, cached plan | 0.125 / 0.114 / 0.115 ms | 0.43 / 0.49 / 0.38 ms | ≤ 0.15 / ≤ 1 ms | met |
| Admission, cold analyze | 0.63 / 0.50 / 0.39 ms | 1.2 / 2.3 / 1.4 ms | ≤ 1 / ≤ 5 ms | met |
| Query-mode overhead vs raw DataFusion | 0.40 / 0.504 / 0.15 ms | noise-dominated (−3.2 / −1.2 / 22 ms) | ≤ 0.5 / ≤ 2 ms | p50 met in 2 of 3 (run 2 misses by 4 µs); p99 not resolvable on a loaded host |
| Kernel instantiate | 0.005 / 0.005 / 0.005 ms | 0.026 / 0.021 / 0.09 ms | ≤ 0.05 / ≤ 0.5 ms | met |
| Kernel fixed overhead | 0.30 / 0.30 / 0.28 ms | 0.51 / 0.56 / 2.0 ms | ≤ 1 / ≤ 5 ms | met |
| Throughput, trivial query (cached) | 4,126 / 3,458 / 2,796 /s | | ≥ 2,000 /s | met |
| Throughput, trivial kernels | 984 / 1,544 / 1,583 /s | | ≥ 1,000 /s | met in 2 of 3 |

The overhead row subtracts two separately measured distributions, so under load its
p99 is meaningless (it can be negative). Engines start from Wizer snapshots and
Cedar entity stores are cached per principal; both matter for the kernel and
admission rows.

### Fuel calibration (`remit bench --calibrate`)

Boa on the same host: 0.094 (compute), 0.124 (objects), 0.109 (arrays) ns per fuel;
published mean 0.109. Fuel was identical across repeated runs of each kernel.

### Instruction counts

`cargo bench -p remit-bench --features callgrind --bench instructions` counts
instructions for admission and instantiation under Callgrind; CI fails a pull
request that regresses either by more than 5 %. Use x86-64 for baselines: on
aarch64, Callgrind's call tracking is unreliable for these paths.

## RemitBench

`node bench/remitbench/run.ts --spawn`: 208 scripted tasks over four Holders, with
process isolation. "Baseline" is an MCP-tools arm whose tools return records. Both
arms are **reference solutions, not LLMs**: accuracy shows expressiveness, and token
numbers are bytes / 4.

| Domain | Tasks | Baseline correct | Remit correct | Bytes crossing the boundary |
|---|---|---|---|---|
| personal | 53 | 100 % | 100 % | −98.9 % |
| enterprise | 54 | 100 % | 100 % | −99.997 % |
| documents | 50 | 100 % | 100 % | −99.7 % |
| b2b | 51 | 100 % | 100 % | −99.9995 % |

Round trips on multi-step tasks: 30 → 15 (−50 %). Median worst-case leakage: 14
bits per task; 4,561 bits over all 208 tasks.

**Adversarial track** (`node bench/remitbench/adversarial.ts`): of 8 planted
injection strings, 8 reach the model context in the baseline and 0 with Remit; 8
exfiltration techniques (extra items, out-of-range values, extra fields, long
strings, sub-precision floats, error text, NaN payloads, `toJSON`) leaked 0 bits
beyond capacity; a one-bit-per-remit campaign recovered 65 bits for 260 charged
and was then stopped by the budget.

## Measuring LLM authors

`bench/remitbench/author.ts` runs an authoring study (60 tasks × query and kernel
mode) against any author command, including `openrouter.ts` for hosted models. It
reports first-try admission, correctness, and admission within two repairs. The
numbers above come from scripted reference solutions only; agent accuracy, real
token counts and injection *success* rates depend on the model and are measured
with this harness.
