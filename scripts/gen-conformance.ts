// Generates spec/conformance vectors with the TS oracle. The Rust
// conformance test re-derives every expected value independently; any
// disagreement fails CI (differential testing).
import { writeFileSync } from "node:fs";
import { canonicalize } from "../sdk/ts/src/jcs.ts";
import { capacity, capacityCeil } from "../sdk/ts/src/types.ts";
import { remitId, paramsSha256 } from "../sdk/ts/src/manifest.ts";

const P = { from: "2026-11-24T00:00:00Z", until: "2026-12-08T00:00:00Z", minutes: 120, n: 7 };
const types: [string, any, any][] = [
  ["bool", "bool", {}],
  ["int-small", { int: { min: 0, max: 255 } }, {}],
  ["int-neg", { int: { min: -1000, max: 1000 } }, {}],
  ["int-param", { int: { min: 0, max: "$n" } }, P],
  ["float-precision", { float: { min: 0, max: 1, precision: 0.01 } }, {}],
  ["date-dst", { date: { min: "2026-03-08", max: "2026-03-09" } }, {}],
  ["date-bound-granularity", { date: { min: "2026-01-01", max: "2026-01-08", granularity: "$grid" } }, { grid: "1d" }],
  ["decimal-midpoint", { decimal: { min: 0, max: 0.5, scale: 0 } }, {}],
  ["float-null-precision", { float: { min: 0, max: 1, precision: null } } as any, {}],
  ["float-unquantized", { float: { min: 0, max: 1 } }, {}],
  ["decimal", { decimal: { scale: 2, min: 0, max: 1000 } }, {}],
  ["enum-3", { enum: ["EMEA", "AMER", "APAC"] }, {}],
  ["enum-1", { enum: ["only"] }, {}],
  ["string-digits", { string: { max_len: 4, charset: "digits" } }, {}],
  ["string-hex-mixed-case", { string: { max_len: 24, charset: "hex" } }, {}],
  ["string-base64-alphabets", { string: { max_len: 512, charset: "base64" } }, {}],
  ["string-unicode", { string: { max_len: 16 } }, {}],
  ["timestamp-15m-2w", { timestamp: { min: "$from", max: "$until", granularity: "15m" } }, P],
  ["timestamp-1h", { timestamp: { min: "2026-01-01T00:00:00Z", max: "2026-01-02T00:00:00Z", granularity: "1h" } }, {}],
  ["date-7d", { date: { min: "2026-01-01", max: "2026-12-31", granularity: "7d" } }, {}],
  ["bytes-16", { bytes: { max_len: 16 } }, {}],
  ["optional-bool", { optional: "bool" }, {}],
  ["list-3-bool", { list: { max: 3, of: "bool" } }, {}],
  ["struct", { struct: { a: "bool", b: { int: { min: 0, max: 3 } } } }, {}],
  ["plan-free-slots", { list: { max: 3, of: { struct: {
      start: { timestamp: { min: "$from", max: "$until", granularity: "15m" } },
      end: { timestamp: { min: "$from", max: "$until", granularity: "15m" } } } } } }, P],
  ["table", { table: { max_rows: 20, of: { struct: { region: { enum: ["EMEA", "AMER", "APAC"] }, arr: { float: { min: 0, max: 1e9, precision: 1000 } } } } } }, {}],
  ["nested-optional-list", { list: { max: 5, of: { optional: { int: { min: 0, max: 99 } } } } }, {}],
];
const cap = types.map(([name, returns, params]) => {
  const bits = capacity(returns, params);
  return { name, returns, params, bits: Math.round(bits * 1e6) / 1e6, bits_ceil: capacityCeil(bits) };
});
const invalid = [
  { name: "string-unbounded", returns: { string: {} }, code: "RMT-E0101", path: "/string/max_len" },
  { name: "list-unbounded", returns: { list: { of: "bool" } }, code: "RMT-E0101", path: "/list/max" },
  { name: "bare-int", returns: "int", code: "RMT-E0101" },
  { name: "unknown", returns: { wat: {} }, code: "RMT-E0102" },
  { name: "unresolved-param", returns: { int: { min: 0, max: "$nope" } }, code: "RMT-E0104" },
  { name: "unknown-charset", returns: { string: { max_len: 2, charset: "upper" } }, code: "RMT-E0103", path: "/string/charset" },
  { name: "timestamp-overflow", returns: { timestamp: { min: -9000000000000000000, max: 9000000000000000000, granularity: 1 } }, code: "RMT-E0103" },
  { name: "zero-granularity", returns: { timestamp: { min: 0, max: 10, granularity: 0 } }, code: "RMT-E0107" },
  { name: "negative-max", returns: { list: { max: -1, of: "bool" } }, code: "RMT-E0103" },
  { name: "huge-list", returns: { list: { max: 16777217, of: "bool" } }, code: "RMT-E0106" },
  { name: "duplicate-enum", returns: { enum: ["a", "a"] }, code: "RMT-E0103" },
  { name: "empty-enum", returns: { enum: [] }, code: "RMT-E0106" },
  { name: "bad-day", returns: { date: { min: "2026-02-30", max: "2026-03-01" } }, code: "RMT-E0103" },
  { name: "zero-precision", returns: { float: { min: 0, max: 1, precision: 0 } }, code: "RMT-E0103" },
  { name: "table-of-scalar", returns: { table: { max_rows: 2, of: "bool" } }, code: "RMT-E0103" },
  { name: "empty-range", returns: { int: { min: 5, max: 1 } }, code: "RMT-E0105" },
];
writeFileSync("spec/conformance/capacity.json", JSON.stringify({ valid: cap, invalid }, null, 2) + "\n");

const jcsInputs: any[] = [
  { b: 2, a: 1, c: { z: [3, 2, 1], y: null } },
  { "€": "euro", "\r": "cr", "1": "one", "😀": "smile", "ﬁ": "fi" },
  [1e30, 4.5, 0.002, 1e-27, -0, 333333333.33333329, 100, 1e21, 123456789012345680000],
  { s: "\u0000\u001f\b\f\n\r\t\"\\/ é" },
  { nested: { deep: { deeper: [true, false, null, { k: "v" }] } } },
];
writeFileSync("spec/conformance/jcs.json", JSON.stringify(jcsInputs.map((input) => ({ input, canonical: canonicalize(input) })), null, 2) + "\n");

const base = (extra: any) => ({
  remit: "0.1", sender: "did:web:travel-agent.example", holder: "did:web:alice.vault.example",
  issued_at: "2026-11-21T10:00:00Z", expires_at: "2026-11-21T10:05:00Z", nonce: "q3V0aaaaaaaa", purpose: "scheduling",
  limits: { fuel: 20000000, memory_bytes: 16777216, wall_ms: 250, output_bytes: 1024 },
  ...extra,
});
const manifests = [
  base({ mode: "query", reads: { q: { sql: "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region", max_rows: 20, max_calls: 1 } }, params: {},
    returns: { list: { max: 20, of: { struct: { region: { enum: ["EMEA", "AMER", "APAC"] }, arr: { float: { min: 0, max: 1e9, precision: 1000 } } } } } } }),
  base({ mode: "kernel", reads: { busy: { sql: "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from", params: { from: "timestamp", until: "timestamp" }, max_rows: 500, max_calls: 1 } },
    code: { lang: "js/es2023", entry: "main", source_sha256: "9f2c" + "0".repeat(60) },
    params: { from: "2026-11-24T00:00:00Z", until: "2026-12-08T00:00:00Z", minutes: 120 },
    returns: { list: { max: 3, of: { struct: { start: { timestamp: { min: "$from", max: "$until", granularity: "15m" } }, end: { timestamp: { min: "$from", max: "$until", granularity: "15m" } } } } } } }),
  base({ mode: "query", purpose: "analytics", limits: { epsilon: 0.3 }, reads: { q: { sql: "SELECT COUNT(*) AS n FROM finance.arr_dp", max_rows: 1, max_calls: 1 } }, returns: { int: { min: 0, max: 100000 } } }),
];
writeFileSync("spec/conformance/remit_id.json", JSON.stringify(manifests.map((m) => ({ manifest: m, remit_id: remitId(m as any), params_sha256: paramsSha256(m as any) })), null, 2) + "\n");

const sql = {
  accept: [
    "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'",
    "WITH r AS (SELECT region, arr FROM crm.accounts) SELECT region, SUM(arr) FROM r GROUP BY region HAVING COUNT(*) > 5",
    "SELECT a.region, COUNT(*) FROM crm.accounts a LEFT JOIN crm.deals d ON a.account_id = d.account_id GROUP BY 1 ORDER BY 2 DESC LIMIT 5",
    "SELECT date_trunc('week', start_at) AS w, COUNT(*) FROM calendar.events GROUP BY 1",
    "SELECT region, row_number() OVER (ORDER BY arr DESC) FROM crm.accounts",
  ],
  reject: [
    { sql: "DELETE FROM crm.accounts", code: "RMT-E0202" },
    { sql: "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t) SELECT * FROM t", code: "RMT-E0203" },
    { sql: "SELECT a FROM x.t UNION SELECT a FROM x.u", code: "RMT-E0204" },
    { sql: "SELECT * FROM calendar.events WHERE start_at < now()", code: "RMT-E0205" },
    { sql: "SELECT random()", code: "RMT-E0205" },
    { sql: "SELECT * FROM a.b FULL OUTER JOIN a.c ON true", code: "RMT-E0206" },
    { sql: "SELECT * FROM a.b FOR UPDATE", code: "RMT-E0207" },
    { sql: "SELECT * FROM a.b WHERE x = $1", code: "RMT-E0208" },
  ],
};
writeFileSync("spec/conformance/sql.json", JSON.stringify(sql, null, 2) + "\n");
console.log("conformance vectors written");
