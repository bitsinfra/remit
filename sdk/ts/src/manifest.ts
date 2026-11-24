// Manifest construction, identity hashes and signing.

import { randomBytes } from "node:crypto";
import { canonicalize } from "./jcs.ts";
import { type Envelope, type Identity, MANIFEST_TYPE, sha256Hex, signEnvelope } from "./identity.ts";
import type { ParamType, RT } from "./types.ts";

export interface ReadTemplate {
  sql: string;
  params?: Record<string, ParamType>;
  max_rows: number;
  max_calls?: number;
}

export interface Limits {
  fuel?: number;
  memory_bytes?: number;
  wall_ms?: number;
  scan_rows?: number;
  scan_bytes?: number;
  output_bytes?: number;
  epsilon?: number;
  delta?: number;
  bits?: number;
}

export interface Manifest {
  remit: string;
  sender: string;
  holder: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  purpose: string;
  authority?: string[];
  mode: "query" | "kernel";
  reads: Record<string, ReadTemplate>;
  code?: { lang: string; entry: string; source_sha256: string; source?: string };
  params?: Record<string, unknown>;
  limits: Limits;
  returns: RT;
}

/** Normalize params for the wire: Date → RFC 3339 string. */
export function wireParams(p: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) out[k] = v instanceof Date ? v.toISOString().replace(".000Z", "Z") : v;
  return out;
}

export function remitId(m: Manifest): string {
  const code = m.code ? { lang: m.code.lang, entry: m.code.entry, source_sha256: m.code.source_sha256.replace(/^sha256:/, "").toLowerCase() } : null;
  const reads: Record<string, unknown> = {};
  for (const [k, r] of Object.entries(m.reads)) {
    reads[k] = { sql: r.sql, ...(r.params && Object.keys(r.params).length ? { params: r.params } : {}), max_rows: r.max_rows, max_calls: r.max_calls ?? 1 };
  }
  return "sha256:" + sha256Hex(canonicalize({ remit: m.remit, mode: m.mode, purpose: m.purpose, reads, code, limits: stripUndefined(m.limits), returns: m.returns }));
}

export function paramsSha256(m: Manifest): string {
  return "sha256:" + sha256Hex(canonicalize(m.params ?? {}));
}

function stripUndefined<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

/** Fill binding fields (sender, timestamps, nonce) for a fresh submission. */
export function bind(m: Omit<Manifest, "sender" | "issued_at" | "expires_at" | "nonce" | "remit"> & Partial<Manifest>, id: Identity, ttlSeconds = 300): Manifest {
  const now = new Date();
  const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
  return {
    ...m,
    remit: m.remit ?? "0.1",
    sender: id.id,
    issued_at: iso(now),
    expires_at: iso(new Date(+now + ttlSeconds * 1000)),
    nonce: randomBytes(16).toString("hex"),
    limits: stripUndefined(m.limits ?? {}),
  } as Manifest;
}

/** JCS-canonicalize and wrap in a DSSE envelope. */
export function signManifest(m: Manifest, id: Identity): Envelope {
  const clean = JSON.parse(JSON.stringify(m)); // drop undefined
  for (const r of Object.values(clean.reads) as any[]) {
    r.max_calls ??= 1;
    if (r.params && Object.keys(r.params).length === 0) delete r.params;
  }
  return signEnvelope(MANIFEST_TYPE, Buffer.from(canonicalize(clean)), id);
}

export function codeBlock(source: string, entry = "main", lang = "js/es2023") {
  return { lang, entry, source, source_sha256: sha256Hex(source) };
}

const SIZE: Record<string, number> = { b: 1, kb: 1e3, kib: 1024, mb: 1e6, mib: 1 << 20, gb: 1e9, gib: 1 << 30 };

export function parseBytes(v: number | string): number {
  const m = typeof v === "string" ? /^(\d+(?:\.\d+)?)\s*([a-z]+)?$/i.exec(v.trim()) : null;
  const bytes = typeof v === "number" ? v : m ? Math.round(Number(m[1]) * SIZE[(m[2] ?? "b").toLowerCase()]) : NaN;
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error(`bad size ${v}`);
  return bytes;
}

export function parseMs(v: number | string): number {
  if (typeof v === "number") return v;
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|min)?$/.exec(v.trim());
  if (!m) throw new Error(`bad duration ${v}`);
  return Math.round(Number(m[1]) * ({ ms: 1, s: 1000, m: 60000, min: 60000 }[(m[2] ?? "ms") as "ms"]));
}

/** SDK-friendly limits: `{ wall: "250ms", memory: "16MiB", output: "1KiB", fuel }`. */
export function limits(l: Record<string, unknown> = {}): Limits {
  const out: Limits = {};
  if (l.fuel !== undefined) out.fuel = Number(l.fuel);
  if (l.wall !== undefined || l.wall_ms !== undefined) out.wall_ms = parseMs((l.wall ?? l.wall_ms) as string);
  if (l.memory !== undefined || l.memory_bytes !== undefined) out.memory_bytes = parseBytes((l.memory ?? l.memory_bytes) as string);
  if (l.output !== undefined || l.output_bytes !== undefined) out.output_bytes = parseBytes((l.output ?? l.output_bytes) as string);
  for (const k of ["scan_rows", "scan_bytes", "epsilon", "delta", "bits"] as const) if (l[k] !== undefined) (out as any)[k] = l[k];
  return out;
}
