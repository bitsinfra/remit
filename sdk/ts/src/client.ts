// Sender client: catalog fetch + verification, local checks, signing,
// submission, counter-offer handling, typed results with receipts.

import * as nodeModule from "node:module";
import { canonicalize } from "./jcs.ts";
import { estimateFuel, type FuelEstimate } from "./fuel.ts";
import { signRequest } from "./httpsig.ts";
import { CATALOG_TYPE, type Envelope, Identity, openEnvelope, pae, publicKeyFromDidKey, RECEIPT_TYPE, sha256Hex, signEnvelope, verifySignature } from "./identity.ts";
import { bind, codeBlock, limits as parseLimits, type Manifest, paramsSha256, type ReadTemplate, remitId, signManifest, wireParams } from "./manifest.ts";
import { capacity, capacityCeil, type ParamRef, type ParamType, revive, type RT, type SchemaLike, STATUS_BITS, toRT } from "./types.ts";
import { kernelDts, transpile, typecheckKernel } from "./typecheck.ts";
import { localVerifier, type Verifier } from "./verifier.ts";

export interface Diagnostic {
  code: string;
  path: string;
  span?: [number, number];
  message: string;
  hint?: string;
  docs?: string;
  fix?: unknown[];
}

export class RemitError extends Error {
  decision: string;
  diagnostics: Diagnostic[];
  response: any;
  constructor(decision: string, diagnostics: Diagnostic[], response: any) {
    super(`${decision}: ${diagnostics.map((d) => `${d.code} ${d.path}: ${d.message}${d.hint ? ` (hint: ${d.hint})` : ""}`).join("; ") || response?.status || "failed"}`);
    this.decision = decision;
    this.diagnostics = diagnostics;
    this.response = response;
  }
}

export interface Receipt {
  run_id: string;
  remit_id: string;
  params_sha256: string;
  sender: string;
  holder: string;
  status: string;
  decision: string;
  execution?: { issued_at: string; nonce: string };
  result_sha256?: string;
  result_bits_max: number;
  labels: string[];
  terms: { retain_days?: number; forward: boolean };
  charged: { bits: number; epsilon: number };
  data_versions: Record<string, string>;
  [k: string]: unknown;
}

export interface RemitResult<T> {
  value: T;
  status: string;
  labels: string[];
  terms: { retain_days?: number; forward: boolean };
  provenance: { holder: string; remit_id: string; params_sha256: string };
  /** Signed receipt envelope (verifiable against the Holder key). */
  receiptEnvelope: Envelope;
  /** Verified receipt body. */
  receipt: Receipt;
  usage: Record<string, string>;
  cached: boolean;
}

/** Bounds within which counter-offers are accepted automatically. */
export interface AutoAccept {
  minWallMs?: number;
  minFuel?: number;
  minMemoryBytes?: number;
  minOutputBytes?: number;
}

export interface RemitOptions {
  identity: Identity;
  fetch?: typeof fetch;
  autoAccept?: AutoAccept | false;
  verifier?: Verifier;
  /** Wrap result strings as Untrusted (default true). */
  untrustedStrings?: boolean;
  /** Sign every request with RFC 9421 HTTP message signatures (default true). */
  signRequests?: boolean;
  /** Type-check TS kernels before sending (default: when a compiler is installed). */
  typecheck?: boolean;
  /** Upload code larger than this once and reference it by hash (default 32 KiB). */
  inlineCodeBytes?: number;
  /** Retries on `429` / busy (default 3). */
  retries?: number;
  /** Extra headers (e.g. WIMSE workload tokens) per request. */
  headers?: (method: string, url: string) => Record<string, string> | Promise<Record<string, string>>;
}

/** A read template built with `holder.sql\`…\`` */
export class ReadBuilder {
  sql: string;
  params: Record<string, ParamType | undefined>;
  _maxRows = 1000;
  _maxCalls = 1;
  constructor(sql: string, params: Record<string, ParamType | undefined>) {
    this.sql = sql;
    this.params = params;
  }
  maxRows(n: number) {
    this._maxRows = n;
    return this;
  }
  maxCalls(n: number) {
    this._maxCalls = n;
    return this;
  }
}

function inferType(v: unknown): ParamType {
  if (v instanceof Date) return "timestamp";
  if (typeof v === "number") return Number.isInteger(v) ? "int" : "float";
  if (typeof v === "boolean") return "bool";
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v)) return "timestamp";
  return "string";
}

export class Remit {
  readonly identity: Identity;
  readonly fetch: typeof fetch;
  readonly autoAccept: AutoAccept | false;
  readonly verifier: Verifier;
  readonly untrustedStrings: boolean;
  readonly signRequests: boolean;
  readonly typecheck: boolean;
  readonly inlineCodeBytes: number;
  readonly retries: number;
  readonly headers: NonNullable<RemitOptions["headers"]>;
  static identity = { fromEnv: () => Identity.fromEnv(), generate: (id?: string) => Identity.generate(id), load: (p: string) => Identity.load(p) };

  constructor(o: RemitOptions) {
    this.identity = o.identity;
    this.fetch = o.fetch ?? fetch;
    this.autoAccept = o.autoAccept ?? {};
    this.verifier = o.verifier ?? localVerifier();
    this.untrustedStrings = o.untrustedStrings ?? true;
    this.signRequests = o.signRequests ?? true;
    this.typecheck = o.typecheck ?? true;
    this.inlineCodeBytes = o.inlineCodeBytes ?? 32 * 1024;
    this.retries = o.retries ?? 3;
    this.headers = o.headers ?? (() => ({}));
  }

  /** Fetch + verify a Holder's catalog. `pin` is the expected `did:key`. */
  async holder(url: string, o: { pin?: string; scoped?: boolean } = {}): Promise<Holder> {
    const base = url.replace(/\/$/, "");
    let r = await this.fetch(`${base}/.well-known/remit`);
    if (!r.ok) throw new Error(`catalog fetch failed: ${r.status}`);
    let catalog = await r.json();
    verifyCatalog(catalog, r.headers.get("remit-signature"), o.pin);
    if (o.scoped) {
      // Ask again as ourselves: the catalog is scoped per principal.
      const body = canonicalize({ holder: catalog.holder, principal: this.identity.id, ts: Date.now() });
      const proof = Buffer.from(JSON.stringify(signEnvelope("application/vnd.remit.catalog-request+json", Buffer.from(body), this.identity))).toString("base64");
      r = await this.fetch(`${base}/.well-known/remit`, { headers: { "remit-proof": proof } });
      const scoped = await r.json();
      verifyCatalog(scoped, r.headers.get("remit-signature"), catalog.keys[0].did_key);
      catalog = scoped;
    }
    return new Holder(this, base, catalog);
  }
}

export function verifyCatalog(catalog: any, sigHeader: string | null, pin?: string) {
  if (!sigHeader) throw new Error("catalog is unsigned");
  const sig = /sig="([^"]+)"/.exec(sigHeader)?.[1];
  const dk: string | undefined = catalog?.keys?.[0]?.did_key;
  if (!sig || !dk) throw new Error("catalog signature header or key missing");
  if (pin && pin !== dk) throw new Error(`catalog key ${dk} does not match pinned ${pin}`);
  const pk = publicKeyFromDidKey(dk)!;
  if (!verifySignature(pk, pae(CATALOG_TYPE, Buffer.from(canonicalize(catalog))), Buffer.from(sig, "base64"))) {
    throw new Error("catalog signature does not verify");
  }
}

type Program = {
  mode: "query" | "kernel";
  reads: Record<string, ReadTemplate>;
  code?: ReturnType<typeof codeBlock>;
  params: Record<string, unknown>;
  returns: RT;
  limits: ReturnType<typeof parseLimits>;
  purpose: string;
  authority?: string[];
};

export class Holder {
  readonly remit: Remit;
  readonly url: string;
  readonly catalog: any;
  readonly id: string;
  readonly holderKey: Uint8Array;

  constructor(remit: Remit, url: string, catalog: any) {
    this.remit = remit;
    this.url = url;
    this.catalog = catalog;
    this.id = catalog.holder;
    this.holderKey = publicKeyFromDidKey(catalog.keys[0].did_key)!;
  }

  get catalogSha256(): string {
    return this.catalog.catalog_sha256;
  }

  /** Published enum values: `"crm.accounts.region"` or shorthand `"crm.region"`. */
  enums(path: string): string[] {
    const parts = path.split(".");
    const col = parts.pop()!;
    const prefix = parts.join(".");
    for (const r of this.catalog.resources ?? []) {
      if (r.name === prefix || r.name.startsWith(prefix + ".")) {
        const c = (r.columns ?? []).find((c: any) => c.name === col && Array.isArray(c.enum));
        if (c) return c.enum;
      }
    }
    throw new Error(`no published enum for ${path}`);
  }

  /** Template tag for read templates: params become `$name` placeholders. */
  sql(strings: TemplateStringsArray, ...values: (ParamRef | string | number)[]): ReadBuilder {
    let sql = "";
    const params: Record<string, ParamType | undefined> = {};
    strings.forEach((s, i) => {
      sql += s;
      if (i < values.length) {
        const v = values[i];
        if (typeof v === "object" && v && "__remitParam" in v) {
          sql += `$${v.__remitParam}`;
          params[v.__remitParam] = v.type;
        } else {
          throw new TypeError("interpolate only t.param(...) into SQL (never raw values)");
        }
      }
    });
    return new ReadBuilder(sql.replace(/\s+/g, " ").trim(), params);
  }

  /** Query mode: one root SQL query is the result. */
  async query<T = unknown>(o: { sql: string; returns: SchemaLike; params?: Record<string, unknown>; limits?: Record<string, unknown>; purpose?: string; maxRows?: number; authority?: string[] }): Promise<RemitResult<T>> {
    const params = o.params ?? {};
    const sqlParams = [...o.sql.matchAll(/\$([A-Za-z_]\w*)/g)].map((m) => m[1]);
    const ptypes: Record<string, ParamType> = {};
    for (const p of sqlParams) ptypes[p] = inferType(params[p]);
    const returns = toRT(o.returns);
    const maxRows = o.maxRows ?? listMax(returns) ?? 1000;
    return this.run<T>({
      mode: "query",
      reads: { q: { sql: o.sql, params: ptypes, max_rows: maxRows, max_calls: 1 } },
      params,
      returns,
      limits: parseLimits(o.limits),
      purpose: o.purpose ?? this.defaultPurpose(),
      authority: o.authority,
    });
  }

  /** Kernel mode: orchestrate declared reads with code, return a tiny answer. */
  async kernel<T = unknown>(o: {
    reads: Record<string, ReadBuilder | ReadTemplate>;
    params?: Record<string, unknown>;
    returns: SchemaLike;
    source: string;
    entry?: string;
    /** `js/es2023` (default; TS is stripped) or `python/monty`. */
    lang?: string;
    limits?: Record<string, unknown>;
    purpose?: string;
    authority?: string[];
  }): Promise<RemitResult<T>> {
    const params = o.params ?? {};
    const lang = o.lang ?? "js/es2023";
    const reads: Record<string, ReadTemplate> = {};
    for (const [k, r] of Object.entries(o.reads)) {
      if (r instanceof ReadBuilder) {
        const ps: Record<string, ParamType> = {};
        for (const [p, ty] of Object.entries(r.params)) ps[p] = ty ?? inferType(params[p]);
        reads[k] = { sql: r.sql, params: ps, max_rows: r._maxRows, max_calls: r._maxCalls };
      } else reads[k] = r;
    }
    const returns = toRT(o.returns);
    // Plain JavaScript is not held to strict TypeScript; annotated kernels are.
    if (lang.startsWith("js") && this.remit.typecheck && toJs(o.source) !== o.source && (o.entry ?? "main") === "main") {
      const dts = kernelDts({ reads, params, returns, catalog: this.catalog, verifier: this.remit.verifier });
      const errs = typecheckKernel(o.source, dts);
      if (errs?.length) throw new RemitError("rejected_locally", errs, null);
    }
    return this.run<T>({
      mode: "kernel",
      reads,
      code: codeBlock(lang.startsWith("js") ? toJs(o.source) : o.source, o.entry ?? "main", lang),
      params,
      returns,
      limits: parseLimits(o.limits),
      purpose: o.purpose ?? this.defaultPurpose(),
      authority: o.authority,
    });
  }

  /** Fuel estimate at the declared caps, from the catalog's price list. */
  estimateFuel(m: Pick<Manifest, "mode" | "reads" | "code">): FuelEstimate {
    return estimateFuel(m, this.catalog);
  }

  private defaultPurpose(): string {
    return this.catalog.purposes?.[0] ?? "unspecified";
  }

  /** Local checks with the same verifier the Holder runs (minus private policy). */
  localCheck(m: Manifest): Diagnostic[] {
    const d: Diagnostic[] = [];
    for (const [name, r] of Object.entries(m.reads)) {
      const v = this.remit.verifier;
      const bound = v.bindSql ? v.bindSql(r.sql, this.catalog) : null;
      const e = bound ? (bound.ok ? null : bound.error!) : v.checkSql(r.sql);
      if (e) d.push({ ...e, path: `/reads/${name}/sql` });
    }
    if (m.limits.fuel !== undefined) {
      const est = this.estimateFuel(m);
      if (est.total > m.limits.fuel) {
        d.push({ code: "RMT-W0203", path: "/limits/fuel", message: `at its read caps this kernel may need ≈${est.total} fuel; limits.fuel is ${m.limits.fuel}`, hint: "lower max_rows / max_calls or raise limits.fuel" });
      }
    }
    let bits = 0;
    try {
      bits = capacityCeil(capacity(m.returns, m.params ?? {})) + STATUS_BITS;
    } catch (e: any) {
      d.push({ code: e.code ?? "RMT-E0101", path: `/returns${e.path ?? ""}`, message: e.message });
    }
    // Public policy hints.
    for (const r of this.catalog.resources ?? []) {
      const used = Object.values(m.reads).some((x) => new RegExp(`\\b${r.name.replace(".", "\\.")}\\b`, "i").test(x.sql));
      if (!used) continue;
      const h = r.hints ?? {};
      if (h.max_bits_per_remit && bits > h.max_bits_per_remit) {
        d.push({ code: "RMT-W0201", path: "/returns", message: `result can carry ${bits} bits; \`${r.name}\` allows ≤ ${h.max_bits_per_remit} per remit`, hint: "tighten list max / granularity / precision" });
      }
      if (h.purposes && !h.purposes.includes(m.purpose)) {
        d.push({ code: "RMT-W0202", path: "/purpose", message: `\`${r.name}\` serves purposes ${h.purposes.join(", ")}`, fix: [{ op: "replace", path: "/purpose", value: h.purposes[0] }] });
      }
    }
    return d;
  }

  async check(p: Program) {
    const m = this.build(p);
    return this.post("check", signManifest(m, this.remit.identity));
  }

  private build(p: Program): Manifest {
    return bind({ holder: this.id, purpose: p.purpose, mode: p.mode, reads: p.reads, code: p.code, params: wireParams(p.params), limits: p.limits, returns: p.returns, ...(p.authority?.length ? { authority: p.authority } : {}) }, this.remit.identity);
  }

  async post(action: "check" | "run", env: Envelope): Promise<any> {
    const url = `${this.url}/remit/v1/${action}`;
    const body = JSON.stringify(env);
    const r = await this.remit.fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/vnd.remit.envelope+json",
        ...(this.remit.signRequests ? signRequest(this.remit.identity, "POST", url, body) : {}),
        ...(await this.remit.headers("POST", url)),
      },
      body,
    });
    const v = await r.json();
    if (r.status === 429) v.retry_after_s = Number(r.headers.get("retry-after") ?? v.retry_after_s ?? 1);
    return v;
  }

  /** Upload code once; later manifests reference it by hash. */
  async putBlob(source: string): Promise<string> {
    const sha = sha256Hex(source);
    const r = await this.remit.fetch(`${this.url}/remit/v1/blobs/${sha}`, { method: "PUT", body: source });
    if (!r.ok) throw new Error(`blob upload failed: ${r.status}`);
    return sha;
  }

  async run<T = unknown>(p: Program): Promise<RemitResult<T>> {
    if (!this.remit.verifier.validate) throw new Error("a result verifier is required");
    let m = this.build(p);
    const local = this.localCheck(m).filter((d) => !d.code.startsWith("RMT-W"));
    if (local.length) throw new RemitError("rejected_locally", local, null);
    if (p.code?.source && Buffer.byteLength(p.code.source) > this.remit.inlineCodeBytes) {
      await this.putBlob(p.code.source);
      const { source: _drop, ...code } = p.code;
      p = { ...p, code: code as any };
      m = this.build(p);
    }
    let busy = 0;
    for (let attempt = 0; attempt < 2; attempt++) {
      const resp = await this.post("run", signManifest(m, this.remit.identity));
      if (resp.decision === "busy" && busy < this.remit.retries) {
        busy++;
        attempt--;
        await new Promise((r) => setTimeout(r, (resp.retry_after_s ?? 1) * 1000));
        m = this.build(p);
        continue;
      }
      if (resp.decision === "counter_offer" && attempt === 0 && this.acceptable(resp.counter_offer?.json_patch ?? [])) {
        for (const op of resp.counter_offer.json_patch) applyOp(p as any, op);
        m = this.build(p);
        continue;
      }
      if (resp.decision && resp.decision !== "admitted") throw new RemitError(resp.decision, resp.diagnostics ?? [], resp);
      const receipt = this.verifyReceipt(resp.receipt);
      if (resp.status !== "ok") throw new RemitError(resp.status, [], resp);
      if (receipt.status !== "ok" || receipt.decision !== "admitted") throw new Error("receipt does not record a successful run");
      if (receipt.remit_id !== remitId(m) || receipt.params_sha256 !== paramsSha256(m)) throw new Error("receipt does not match the submitted remit");
      if (receipt.holder !== this.id || receipt.sender !== this.remit.identity.id) throw new Error("receipt names different parties");
      if (receipt.result_sha256 !== `sha256:${sha256Hex(canonicalize(resp.result))}`) throw new Error("result does not match the signed receipt");
      // The Holder is not trusted either: the value must inhabit the declared type.
      const val = this.remit.verifier.validate(m.returns, m.params ?? {}, resp.result);
      if (!val?.ok || canonicalize(val.value) !== canonicalize(resp.result)) throw new Error(`result does not inhabit the declared type: ${val?.error ?? "non-canonical value"}`);
      const src = { holder: this.id, remit_id: receipt.remit_id };
      return {
        value: revive(resolveRt(m.returns, m.params ?? {}), resp.result, src, this.remit.untrustedStrings) as T,
        status: resp.status,
        labels: receipt.labels,
        terms: receipt.terms,
        provenance: resp.provenance,
        receiptEnvelope: resp.receipt,
        receipt,
        usage: resp.usage,
        cached: resp.cached,
      };
    }
    throw new Error("counter-offer loop");
  }

  private acceptable(patch: any[]): boolean {
    const a = this.remit.autoAccept;
    if (!a) return false;
    return patch.every((op) => {
      const v = op.value;
      switch (op.path) {
        case "/limits/wall_ms": return v >= (a.minWallMs ?? 0);
        case "/limits/fuel": return v >= (a.minFuel ?? 0);
        case "/limits/memory_bytes": return v >= (a.minMemoryBytes ?? 0);
        case "/limits/output_bytes": return v >= (a.minOutputBytes ?? 0);
        default: return false;
      }
    });
  }

  /** Verify a receipt envelope against this Holder's key. */
  verifyReceipt(env: Envelope): Receipt {
    return JSON.parse(Buffer.from(openEnvelope(env, RECEIPT_TYPE, this.holderKey)).toString("utf8"));
  }
}

function applyOp(p: Program, op: { op: string; path: string; value: unknown }) {
  const [, top, key] = op.path.split("/");
  if (top === "limits" && key) (p.limits as any)[key] = op.value;
}

function listMax(rt: RT): number | undefined {
  if (typeof rt === "object" && "list" in rt && typeof rt.list.max === "number") return rt.list.max;
  if (typeof rt === "object" && "table" in rt && typeof rt.table.max_rows === "number") return rt.table.max_rows;
  return undefined;
}

/** Bounds with params resolved (only needed for revival; shapes are unchanged). */
function resolveRt(rt: RT, _params: Record<string, unknown>): RT {
  return rt;
}

/** Strip TypeScript types (only source is sent; the Holder never compiles TS). */
export function toJs(source: string): string {
  // Node ≥ 22.13 strips types natively; older runtimes use an installed compiler.
  const strip = (nodeModule as { stripTypeScriptTypes?: (s: string, o: { mode: "strip" }) => string }).stripTypeScriptTypes;
  try {
    if (strip) return strip(source, { mode: "strip" });
  } catch {
    return source;
  }
  return transpile(source) ?? source;
}
