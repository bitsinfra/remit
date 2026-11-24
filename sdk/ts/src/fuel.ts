// Coarse, data-independent fuel estimate from the catalog's published price
// list: an upper bound on priced host work plus a guess for interpreting the
// kernel over the rows it may read.

import type { Manifest } from "./manifest.ts";

/** Interpreter fuel per row touched (measured on typical kernels; `remit bench`). */
const FUEL_PER_ROW_COMPUTE = 6_000;
const FUEL_LOAD_PER_BYTE = 1_500;
const BYTES_PER_ROW = 64;

export interface FuelEstimate {
  /** Priced host work if every read hits its caps. */
  host_max: number;
  /** Rough interpreter cost at the caps. */
  compute: number;
  total: number;
}

export function estimateFuel(m: Pick<Manifest, "mode" | "reads" | "code">, catalog: any): FuelEstimate {
  const p = catalog?.runtime?.fuel_prices ?? { per_call: 50_000, per_row: 200, per_byte: 1 };
  if (m.mode === "query") return { host_max: 0, compute: 0, total: 0 };
  let host = 0;
  let rows = 0;
  for (const r of Object.values(m.reads)) {
    const calls = r.max_calls ?? 1;
    const table = (catalog?.resources ?? []).find((x: any) => new RegExp(`\\b${String(x.name).replace(".", "\\.")}\\b`, "i").test(r.sql));
    const bound = Math.min(r.max_rows, bucketMax(table?.rows) ?? r.max_rows);
    rows += calls * bound;
    host += calls * (p.per_call + bound * (p.per_row + BYTES_PER_ROW * p.per_byte));
  }
  const compute = Math.round(rows * FUEL_PER_ROW_COMPUTE + (m.code?.source?.length ?? 0) * FUEL_LOAD_PER_BYTE);
  return { host_max: host, compute, total: host + compute };
}

/** `"≤10K"` → 10000. */
function bucketMax(b?: string): number | undefined {
  const m = /^≤(\d+)([KMG])?$/.exec(b ?? "");
  return m ? Number(m[1]) * ({ K: 1e3, M: 1e6, G: 1e9 }[m[2] as "K"] ?? 1) : undefined;
}
