// The Holder's verifier for local checks. Prefers the Rust verifier compiled
// to Wasm (`wasm/remit_verify_wasm.js`, built by scripts/build-verifier.sh);
// falls back to a conservative TS subset when the Wasm build is absent.

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export interface SqlDiag {
  code: string;
  message: string;
  span?: [number, number];
  hint?: string;
}

export interface BoundSql {
  columns: { name: string; type: string; nullable: boolean }[];
  reads: Record<string, string[]>;
  aggregate_only: boolean;
}

export interface Verifier {
  kind: "wasm" | "ts";
  checkSql(sql: string): SqlDiag | null;
  /** Bind SQL against a catalog: output columns, lineage, diagnostics. */
  bindSql?(sql: string, catalog: unknown): { ok: boolean; bound?: BoundSql; error?: SqlDiag };
  /** Validate a value against a bounded type. */
  validate?(returns: unknown, params: unknown, value: unknown): { ok: boolean; value?: unknown; error?: string };
  /** Rust capacity (for differential testing), if available. */
  capacity?(returns: unknown, params: unknown): { ok: boolean; bits?: number; bits_ceil?: number; error?: any };
  canonicalize?(v: unknown): string;
  remitId?(manifest: unknown): { remit_id: string; params_sha256: string };
}

let cached: Verifier | null = null;

export function wasmVerifier(): Verifier | null {
  const here = dirname(fileURLToPath(import.meta.url));
  // `src/` in the repo, `dist/src/` in the published package.
  const p = [join(here, "..", "wasm"), join(here, "..", "..", "wasm")].map((d) => join(d, "remit_verify_wasm.js")).find((f) => existsSync(f));
  if (!p) return null;
  const req = createRequire(import.meta.url);
  const w = req(p);
  return {
    kind: "wasm",
    checkSql(sql) {
      const r = JSON.parse(w.check_sql(sql));
      return r.ok ? null : { code: r.error.code, message: r.error.message, span: r.error.span ?? undefined, hint: r.error.hint ?? undefined };
    },
    bindSql(sql, catalog) {
      return JSON.parse(w.bind_sql(sql, JSON.stringify(catalog)));
    },
    validate(returns, params, value) {
      return JSON.parse(w.validate(JSON.stringify(returns), JSON.stringify(params), JSON.stringify(value)));
    },
    capacity(returns, params) {
      return JSON.parse(w.capacity(JSON.stringify(returns), JSON.stringify(params)));
    },
    canonicalize(v) {
      return w.canonicalize(JSON.stringify(v));
    },
    remitId(m) {
      return JSON.parse(w.remit_id(JSON.stringify(m)));
    },
  };
}

const FORBIDDEN_FNS = /\b(now|current_timestamp|current_date|current_time|random|uuid|gen_random_uuid|setseed|pg_sleep)\s*\(/i;
const NOT_QUERY = /^\s*(insert|update|delete|drop|create|alter|truncate|grant|revoke|copy|set|call|do)\b/i;

export function tsVerifier(): Verifier {
  return {
    kind: "ts",
    checkSql(sql) {
      if (NOT_QUERY.test(sql)) return { code: "RMT-E0202", message: "only SELECT queries are allowed (no DDL, DML or utility statements)" };
      if (/with\s+recursive/i.test(sql)) return { code: "RMT-E0203", message: "recursive CTEs are not allowed" };
      if (/\b(union|intersect|except)\b/i.test(sql)) return { code: "RMT-E0204", message: "UNION/INTERSECT/EXCEPT are not in the Remit SQL profile" };
      const f = FORBIDDEN_FNS.exec(sql);
      if (f) return { code: "RMT-E0205", message: `function \`${f[1].toLowerCase()}\` is not in the Remit SQL allowlist`, hint: "time always comes from params" };
      if (/\$\d/.test(sql)) return { code: "RMT-E0208", message: "use named params like `$from`" };
      return null;
    },
  };
}

export function localVerifier(): Verifier {
  if (!cached) {
    try {
      cached = wasmVerifier() ?? tsVerifier();
    } catch {
      cached = tsVerifier();
    }
  }
  return cached;
}
