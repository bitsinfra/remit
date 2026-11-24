# Remit Types (RT)

RT is a small, bounded type system that maps 1:1 to Arrow types plus
constraints. Every remit declares its result type in `returns`; the Holder
computes its **capacity** (bits) before running anything.

## Syntax (wire)

A type is `"bool"` or a single-key object:

| Type | Body | Value encoding (JSON) |
|---|---|---|
| `bool` | `{}` | `true`/`false` |
| `int` | `{min, max}` | integer |
| `float` | `{min, max, precision?}` | number |
| `decimal` | `{scale (0–18), min, max}` | string with `scale` digits |
| `enum` | `["a", …]` or `{values: […]}` (1–65,536 distinct) | string |
| `string` | `{max_len, charset?, pattern?}` | string |
| `timestamp` | `{min, max, granularity}` | RFC 3339 (UTC `Z` on output) |
| `date` | `{min, max, granularity?}` (whole days) | `YYYY-MM-DD` |
| `bytes` | `{max_len}` | base64 |
| `list` | `{max, of}` | array |
| `table` | `{max_rows, of: struct}` | array of objects (Arrow IPC on request) |
| `struct` | `{field: T, …}` | object with exactly the declared fields |
| `optional` | `T` | `null` or T (a missing optional field reads as `null`) |

Charsets: `digits` (10), `hex` (22, including both letter cases), `alpha` (52),
`alnum` (62), `base64` (67, including `+`, `/`, `=`, `-`, and `_`), `ascii` (95
printable), `unicode` (1,112,064; default). String charsets constrain characters
and preserve spelling. Use `bytes` to validate and canonicalize base64-encoded
binary data.

Bounds may be literals or param references (`"$from"`). Durations are
`<n><unit>` with units `ms s m h d w` (`"15m"`, `"1h30m"`).

**Every type must be bounded.** Missing bounds are `RMT-E0101` with a JSON
pointer to the missing field (e.g. `/returns/list/max`); unknown types are
`RMT-E0102`; unresolved params `RMT-E0104`; `min > max` `RMT-E0105`; sizes
above 2²⁴ `RMT-E0106`.

## Capacity

| Type | Capacity (bits) |
|---|---|
| `bool` | 1 |
| `int` | log2(max − min + 1) |
| `float` | log2(⌊(max − min)/precision⌋ + 1); unquantized: 64 |
| `decimal` | log2(round((max − min)·10^scale) + 1) |
| `enum` | log2(n) |
| `string` | max_len·log2(\|charset\|) + log2(max_len + 1) |
| `timestamp`, `date` | log2(⌊(max − min)/granularity⌋ + 1) |
| `bytes` | 8·max_len + log2(max_len + 1) |
| `list`, `table` | log2(max + 1) + max·cap(T) |
| `struct` | Σ cap(fields) |
| `optional` | log2(2^cap(T) + 1) |

`log2(1) = 0`. The charged figure is `result_bits = ⌈capacity⌉ + status_bits`
where `status_bits = ⌈log2 |status set|⌉ = 3` ([status.md](status.md)).

Capacity is a **sound worst-case cap** for arbitrary producing code: the number
of distinct values the emit plane can release is ≤ 2^capacity (property-tested
by exhaustive enumeration in `remit-types`). It is not semantic privacy: 64 bits
can encode an SSN, so it is combined with column policy and DP.

Example (manifest.md): three 15-minute slots over two weeks:
1,345 grid points → 10.39 bits per timestamp; 3 × 2 × 10.39 + log2(4) ≈ **64.35
bits**, charged as 65 + 3 = 68.

## Validation and trusted transforms

After execution the Holder validates the *actual* output against the bound type
and applies trusted transforms before encoding:

- `float` with `precision`: rounded to the nearest grid point `min + k·precision`
  with `0 ≤ k ≤ ⌊(max − min)/precision⌋`. `max` itself is released only if it is on
  the grid.
- `timestamp`/`date`: floored to the granularity grid anchored at `min`.
- `decimal`: rounded to the nearest multiple of 10^−scale inside `[min, max]`; a
  range with no such value admits nothing.
- Range, length, charset, pattern, enum membership, list sizes and struct shape
  are checked exactly; any violation is `type_violation` and **no partial result**
  is released.

Normalization is idempotent. The encoded result is the JCS form of the
normalized value; `result_sha256` hashes it.

## JSON Schema profile

`returns` may instead be a JSON Schema 2020-12 document (detected by `$schema`,
`type` or `anyOf`), as produced by Zod ≥ 4.2, Valibot ≥ 1.2 or ArkType ≥ 2.1.28.
Bounds come from standard keywords (`minimum`, `maximum`, `maxLength`,
`maxItems`, `enum`, `multipleOf` as precision) and `x-remit-*` extensions:
`x-remit-precision`, `x-remit-charset`, `x-remit-minimum`/`x-remit-maximum`/
`x-remit-granularity` (date-time, date), `x-remit-scale`, `x-remit-maxBytes`,
`x-remit-table`. Nullable is `anyOf: [T, {type: null}]` or `type: [T, "null"]`;
non-required object properties become `optional`.

Timestamp bounds and granularities are limited to ±8.64·10¹⁵ ms (the ECMAScript time range), so `max − min` can never overflow into a smaller capacity.
