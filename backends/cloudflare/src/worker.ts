// Remit Holder on Cloudflare Workers (edge profile; see README.md).
import { initSync, bind_sql, canonicalize, capacity, remit_id, validate } from "../../../sdk/ts/wasm/web/remit_verify_wasm.js";
// @ts-ignore: provided as a compiled Wasm module
import verifier from "./remit_verify_wasm_bg.wasm";
import { KERNEL_HOST } from "./kernel_host.ts";

initSync({ module: verifier });

interface Column {
  name: string;
  type: string;
  nullable?: boolean;
  enum?: string[];
}
interface Resource {
  /** D1 view the Holder wrote for this resource (it *is* the policy view). */
  view: string;
  columns: Column[];
  description?: string;
  purposes?: string[];
  groups?: string[];
  max_bits?: number;
  aggregate_only?: boolean;
  labels?: string[];
  retain_days?: number;
}
interface HolderConfig {
  id: string;
  resources: Record<string, Resource>;
  principals: Record<string, { keys: string[]; groups?: string[] }>;
  limits?: { max_rows?: number; cpu_ms?: number; wall_ms?: number; output_bytes?: number };
  budgets?: { bits_per_principal_per_day?: number; bits_global_per_day?: number };
  examples?: unknown[];
}
interface Env {
  DB: D1Database;
  LOADER: { get(id: string, f: () => Promise<any>): { getEntrypoint(name?: string | null): { fetch(r: Request): Promise<Response> } } };
  /** JSON HolderConfig. */
  REMIT_CONFIG: string;
  /** Base64 PKCS#8 Ed25519 key (secret). */
  REMIT_KEY: string;
}

const MANIFEST = "application/vnd.remit.manifest+json", RECEIPT = "application/vnd.remit.receipt+json", CATALOG = "application/vnd.remit.catalog+json";
const STATUS_BITS = 3;
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const te = new TextEncoder(), td = new TextDecoder();
const b64 = (b: Uint8Array) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s: string) => hex(await crypto.subtle.digest("SHA-256", te.encode(s)));
const jcs = (v: unknown) => canonicalize(JSON.stringify(v));

function unb58(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("base58");
    n = n * 58n + BigInt(i);
  }
  const out: number[] = [];
  for (; n > 0n; n >>= 8n) out.unshift(Number(n & 255n));
  return Uint8Array.from(out);
}
function b58(b: Uint8Array): string {
  let n = 0n, s = "";
  for (const x of b) n = (n << 8n) | BigInt(x);
  for (; n > 0n; n /= 58n) s = B58[Number(n % 58n)] + s;
  return s;
}
function pae(type: string, body: Uint8Array): Uint8Array {
  const h = te.encode(`DSSEv1 ${te.encode(type).length} ${type} ${body.length} `);
  const o = new Uint8Array(h.length + body.length);
  o.set(h);
  o.set(body, h.length);
  return o;
}
async function verifySig(didKey: string, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const raw = unb58(didKey.slice("did:key:z".length));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 1) return false;
  const k = await crypto.subtle.importKey("raw", raw.slice(2), "Ed25519", false, ["verify"]);
  return crypto.subtle.verify("Ed25519", k, sig, msg);
}

interface Diag {
  code: string;
  path: string;
  message: string;
  hint?: string;
  span?: unknown;
}
class Reject extends Error {
  diags: Diag[];
  denied: boolean;
  constructor(diags: Diag[], denied = false) {
    super(diags[0]?.message);
    this.diags = diags;
    this.denied = denied;
  }
}
const no = (code: string, path: string, message: string, denied = false) => new Reject([{ code, path, message }], denied);

class Holder {
  env: Env;
  cfg: HolderConfig;
  constructor(env: Env) {
    this.env = env;
    this.cfg = JSON.parse(env.REMIT_CONFIG);
  }
  async key(): Promise<{ priv: CryptoKey; didKey: string; kid: string }> {
    const priv = await crypto.subtle.importKey("pkcs8", unb64(this.env.REMIT_KEY), "Ed25519", true, ["sign"]);
    const jwk: any = await crypto.subtle.exportKey("jwk", priv);
    const pub = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const didKey = "did:key:z" + b58(Uint8Array.from([0xed, 1, ...pub]));
    return { priv, didKey, kid: `${this.cfg.id}#${didKey.slice(8)}` };
  }
  async sign(type: string, text: string) {
    const { priv, kid } = await this.key();
    const body = te.encode(text);
    return { payloadType: type, payload: b64(body), signatures: [{ keyid: kid, sig: b64(new Uint8Array(await crypto.subtle.sign("Ed25519", priv, pae(type, body)))) }] };
  }

  visible(groups: string[]): [string, Resource][] {
    return Object.entries(this.cfg.resources).filter(([, r]) => !r.groups?.length || r.groups.some((g) => groups.includes(g)));
  }

  async catalog(groups: string[]): Promise<any> {
    const { didKey, kid } = await this.key();
    const vis = this.visible(groups);
    const doc: any = {
      remit: "0.1", holder: this.cfg.id, keys: [{ kid, did_key: didKey, alg: "Ed25519" }],
      resources: vis.map(([name, r]) => ({ name, kind: "table", description: r.description ?? null, columns: r.columns.map((c) => ({ nullable: true, ...c })), labels: r.labels ?? [], hints: { aggregate_only: !!r.aggregate_only, ...(r.max_bits ? { max_bits_per_remit: r.max_bits } : {}), ...(r.purposes ? { purposes: r.purposes } : {}) } })),
      policy_hints: vis.map(([n, r]) => `\`${n}\`: columns {${r.columns.map((c) => c.name).join(", ")}}`),
      purposes: [...new Set(vis.flatMap(([, r]) => r.purposes ?? []))].sort(),
      runtime: { modes: ["query", "kernel"], languages: ["js/es2023"], isolation: "cloudflare-dynamic-worker", profile: "edge", status_set: ["ok", "limit_exceeded", "type_violation", "denied", "internal"], status_bits: STATUS_BITS,
        limits: { max_rows_per_read: this.lim.max_rows, max_calls_per_read: 1, max_wall_ms: this.lim.wall_ms, max_output_bytes: this.lim.output_bytes } },
      examples: this.cfg.examples ?? [], stats: {},
      endpoints: { check: "/remit/v1/check", run: "/remit/v1/run", receipts: "/remit/v1/receipts/{id}" },
    };
    doc.catalog_sha256 = `sha256:${await sha(jcs(doc))}`;
    return doc;
  }
  get lim() {
    return { max_rows: 10_000, cpu_ms: 50, wall_ms: 5_000, output_bytes: 65_536, ...this.cfg.limits };
  }

  /** Envelope → verified manifest. */
  async open(text: string): Promise<{ m: any; groups: string[] }> {
    if (text.length > 512 * 1024) throw no("RMT-E0001", "/", "envelope too large");
    let env: any;
    try {
      env = JSON.parse(text);
    } catch {
      throw no("RMT-E0002", "/", "not a DSSE envelope");
    }
    if (env?.payloadType !== MANIFEST || typeof env.payload !== "string" || !Array.isArray(env.signatures)) throw no("RMT-E0010", "/", "not a Remit envelope", true);
    const body = unb64(env.payload);
    let signer: string | null = null;
    for (const s of env.signatures.slice(0, 4)) {
      const [base, frag] = String(s.keyid).split("#");
      const p = this.cfg.principals[base];
      const dk = frag ? `did:key:${frag}` : base;
      if (!p || !p.keys.includes(dk)) continue;
      if (!(await verifySig(dk, pae(MANIFEST, body), unb64(s.sig)))) throw no("RMT-E0010", "/signatures", "bad signature", true);
      signer = base;
      break;
    }
    if (!signer) throw no("RMT-E0010", "/signatures", "no signature from a known key", true);
    const raw = td.decode(body);
    let m: any;
    try {
      m = JSON.parse(raw);
    } catch {
      throw no("RMT-E0003", "/", "manifest is not JSON");
    }
    if (jcs(m) !== raw) throw no("RMT-E0003", "/", "manifest payload is not JCS-canonical");
    try {
      remit_id(raw);
    } catch (e) {
      throw no("RMT-E0003", "/", String(e));
    }
    if (m.sender !== signer) throw no("RMT-E0010", "/sender", "key does not belong to sender", true);
    if (m.holder !== this.cfg.id) throw no("RMT-E0020", "/holder", "addressed to another Holder");
    const now = Date.now(), iat = Date.parse(m.issued_at), exp = Date.parse(m.expires_at);
    if (!(exp > now)) throw no("RMT-E0021", "/expires_at", "the remit has expired");
    if (iat > now + 120_000) throw no("RMT-E0022", "/issued_at", "issued_at is in the future");
    if (exp - iat > 900_000) throw no("RMT-E0023", "/expires_at", "validity window exceeds 900 s");
    return { m, groups: this.cfg.principals[signer].groups ?? [] };
  }

  async analyze(m: any, groups: string[]) {
    const cat = await this.catalog(groups);
    const diags: Diag[] = [];
    const used = new Map<string, Set<string>>();
    const reads: Record<string, { sql: string; args: string[]; columns: Column[] }> = {};
    let rowLevel = false;
    for (const [name, r] of Object.entries<any>(m.reads)) {
      const b = JSON.parse(bind_sql(r.sql, JSON.stringify(cat)));
      if (!b.ok) {
        diags.push({ ...b.error, path: `/reads/${name}/sql` });
        continue;
      }
      if ((r.max_calls ?? 1) !== 1) diags.push({ code: "RMT-E0140", path: `/reads/${name}/max_calls`, message: "the edge profile runs each read once" });
      if (r.max_rows > this.lim.max_rows) diags.push({ code: "RMT-E0140", path: `/reads/${name}/max_rows`, message: `max_rows exceeds ${this.lim.max_rows}` });
      for (const [t, cols] of Object.entries<string[]>(b.bound.reads)) used.set(t, new Set([...(used.get(t) ?? []), ...cols]));
      rowLevel ||= !b.bound.aggregate_only;
      reads[name] = { ...this.rewrite(r.sql), columns: b.bound.columns };
    }
    const cap = JSON.parse(capacity(JSON.stringify(m.returns), JSON.stringify(m.params ?? {})));
    if (!cap.ok) diags.push(cap.error);
    if (diags.length) throw new Reject(diags);
    if (m.mode === "kernel") {
      if (m.code?.lang !== "js/es2023") throw no("RMT-E0151", "/code/lang", "js/es2023 only");
      if (typeof m.code.source !== "string" || (await sha(m.code.source)) !== String(m.code.source_sha256).replace("sha256:", "")) throw no("RMT-E0030", "/code/source", "inline source is required and must match its hash");
      if (/\bimport\b/.test(m.code.source)) throw no("RMT-E0602", "/code/source", "imports are not available to kernels");
    }
    for (const [t] of used) {
      const r = this.cfg.resources[t];
      if (r.purposes?.length && !r.purposes.includes(m.purpose)) throw no("RMT-E0050", "/purpose", `\`${t}\` does not serve this purpose`, true);
      if (r.max_bits !== undefined && cap.result_bits > r.max_bits) throw no("RMT-E0050", "/returns", `result can carry ${cap.result_bits} bits; \`${t}\` allows ${r.max_bits}`, true);
      if (r.aggregate_only && rowLevel) throw no("RMT-E0304", "/reads", `\`${t}\` is aggregate-only`);
    }
    if (!used.size) throw no("RMT-E0050", "/reads", "a remit must read at least one resource", true);
    return { cat, reads, used, bits: cap.result_bits as number };
  }

  /** Remit SQL (already bound) → D1: resources become views, `$p` becomes `?n`. */
  rewrite(sql: string): { sql: string; args: string[] } {
    const args: string[] = [];
    const out = sql.replace(/'(?:[^']|'')*'|--[^\n]*|\/\*[\s\S]*?\*\/|\$([A-Za-z_]\w*)|"?([A-Za-z_]\w*)"?\."?([A-Za-z_]\w*)"?/g, (all, p, a, b) => {
      if (p) {
        let i = args.indexOf(p);
        if (i < 0) i = args.push(p) - 1;
        return `?${i + 1}`;
      }
      if (a && b) {
        const r = this.cfg.resources[`${a}.${b}`.toLowerCase()];
        if (r) return `"${r.view}"`;
      }
      return all.startsWith("--") || all.startsWith("/*") ? " " : all;
    });
    return { sql: out, args };
  }

  async snapshot(a: Awaited<ReturnType<Holder["analyze"]>>, m: any) {
    const names = [...a.used.keys()].sort();
    const reads = Object.entries(a.reads);
    const statements = names.map((name) => this.env.DB.prepare(`SELECT * FROM "${this.cfg.resources[name].view.replaceAll('"', '""')}"`));
    for (const [name, q] of reads) {
      statements.push(this.env.DB.prepare(`SELECT * FROM (${q.sql}) LIMIT ${m.reads[name].max_rows + 1}`).bind(...q.args.map((key) => m.params?.[key] ?? null)));
    }
    const results = await this.env.DB.batch(statements);
    const versions: Record<string, string> = {};
    for (let i = 0; i < names.length; i++) {
      versions[names[i]] = `d1:sha256:${await sha(jcs({ view: this.cfg.resources[names[i]].view, rows: results[i].results.map((row: any) => jcs(row)).sort() }))}`;
    }
    const tables: Record<string, { columns: Column[]; rows: any[][] }> = {};
    for (let i = 0; i < reads.length; i++) {
      const [name, q] = reads[i];
      const rows = results[names.length + i].results;
      if (rows.length > m.reads[name].max_rows) return { versions, tables, status: "limit_exceeded" };
      tables[name] = { columns: q.columns, rows: rows.map((row: any) => q.columns.map((column) => column.type === "bool" && row[column.name] !== null ? !!row[column.name] : row[column.name])) };
    }
    return { versions, tables, status: "ok" };
  }

  async reserve(m: any, bits: number): Promise<number> {
    const day = Math.floor(Date.now() / 86_400_000);
    const b = { bits_per_principal_per_day: 4096, bits_global_per_day: 65_536, ...this.cfg.budgets };
    // One atomic batch: nonce insert, then guarded counters.
    const DB = this.env.DB;
    const nonce = await DB.prepare("INSERT OR IGNORE INTO remit_nonce (k, exp) VALUES (?1, ?2)").bind(await sha(`${m.sender}|${m.nonce}`), Date.parse(m.expires_at)).run();
    if (nonce.meta.changes === 0) throw no("RMT-E0024", "/nonce", "replayed nonce");
    const res = await DB.batch([
      DB.prepare("INSERT INTO remit_bits (scope, day, bits) VALUES (?1, ?2, 0) ON CONFLICT DO NOTHING").bind(`p:${m.sender}`, day),
      DB.prepare("INSERT INTO remit_bits (scope, day, bits) VALUES ('*', ?1, 0) ON CONFLICT DO NOTHING").bind(day),
      DB.prepare(
        `UPDATE remit_bits SET bits = bits + ?1 WHERE day = ?2 AND scope IN (?3, '*')
         AND (SELECT bits FROM remit_bits WHERE scope = ?3 AND day = ?2) + ?1 <= ?4 AND (SELECT bits FROM remit_bits WHERE scope = '*' AND day = ?2) + ?1 <= ?5`,
      ).bind(bits, day, `p:${m.sender}`, b.bits_per_principal_per_day, b.bits_global_per_day),
    ]);
    if (res[2].meta.changes !== 2) throw no("RMT-E0060", "/limits", "bit budget exhausted", true);
    return day;
  }

  async kernel(m: any, tables: Record<string, { columns: Column[]; rows: any[][] }>): Promise<{ status: string; value?: unknown }> {
    const data = `export const __remitTables = ${JSON.stringify(tables)};`;
    // The isolate id covers code *and* data: nothing is shared across remits.
    const id = `remit:${await sha(m.code.source + "\0" + data + "\0" + m.nonce)}`;
    const w = this.env.LOADER.get(id, async () => ({
      compatibilityDate: "2026-01-01",
      mainModule: "host.js",
      modules: { "host.js": KERNEL_HOST, "kernel.js": m.code.source, "data.js": data },
      env: {},
      globalOutbound: null,
      limits: { cpuMs: this.lim.cpu_ms, subRequests: 0 },
    }));
    const wall = Math.min(m.limits?.wall_ms ?? 1000, this.lim.wall_ms);
    const seed = parseInt((await sha(m.nonce)).slice(0, 8), 16);
    const dates = Object.entries(Object.assign({}, ...Object.values<any>(m.reads).map((r) => r.params ?? {}))).filter(([, t]) => t === "timestamp").map(([k]) => k);
    try {
      const run = w.getEntrypoint().fetch(new Request("http://kernel/", { method: "POST", body: JSON.stringify({ now: Date.parse(m.issued_at), seed, params: m.params ?? {}, dates }) }));
      const r = await Promise.race([run, new Promise<null>((res) => setTimeout(() => res(null), wall))]);
      if (!r) return { status: "limit_exceeded" };
      if (!r.ok) return { status: "internal" };
      const text = await r.text();
      if (te.encode(text).byteLength > this.lim.output_bytes * 4) return { status: "limit_exceeded" };
      return { status: "ok", value: JSON.parse(text, (_k, v) => (v && typeof v === "object" && Object.keys(v).length === 1 && typeof v.$d === "number" ? new Date(v.$d).toISOString() : v)) };
    } catch (e: any) {
      // CPU limit exceeded surfaces as a thrown error.
      return { status: /cpu|limit/i.test(String(e?.message)) ? "limit_exceeded" : "internal" };
    }
  }

  async run(text: string): Promise<any> {
    const { m, groups } = await this.open(text);
    if (!m.params) throw no("RMT-E0111", "/params", "templates can be checked but not run");
    const a = await this.analyze(m, groups);
    const day = await this.reserve(m, a.bits);
    let versions: Record<string, string> = {};
    let status = "ok", value: any = null;
    try {
      const snapshot = await this.snapshot(a, m);
      versions = snapshot.versions;
      status = snapshot.status;
      const tables = snapshot.tables;
      if (status === "ok") {
        let v: unknown;
        if (m.mode === "kernel") {
          const k = await this.kernel(m, tables);
          status = k.status;
          v = k.value;
        } else v = shape(m.returns, Object.values(tables)[0]);
        if (status === "ok") {
          const ok = JSON.parse(validate(JSON.stringify(m.returns), JSON.stringify(m.params), JSON.stringify(v)));
          if (!ok.ok) status = "type_violation";
          else if (te.encode(jcs(ok.value)).byteLength > Math.min(m.limits?.output_bytes ?? this.lim.output_bytes, this.lim.output_bytes)) status = "limit_exceeded";
          else value = ok.value;
        }
      }
    } catch {
      status = "internal";
      value = null;
    }
    const ids = JSON.parse(remit_id(jcs(m)));
    const run_id = `run_${hex(crypto.getRandomValues(new Uint8Array(12)).buffer)}`;
    const labels = [...new Set([...a.used.keys()].flatMap((t) => this.cfg.resources[t].labels ?? []))].sort();
    const retain = [...a.used.keys()].map((t) => this.cfg.resources[t].retain_days).filter((x): x is number => x !== undefined);
    const terms = { ...(retain.length ? { retain_days: Math.min(...retain) } : {}), forward: !labels.includes("no-forward") };
    const receipt: any = {
      run_id, remit_id: ids.remit_id, params_sha256: ids.params_sha256, sender: m.sender, holder: this.cfg.id, decision: "admitted", policy_sha256: `sha256:${await sha(this.env.REMIT_CONFIG)}`, catalog_sha256: a.cat.catalog_sha256,
      data_versions: versions, ...(status === "ok" ? { result_sha256: `sha256:${await sha(jcs(value))}` } : {}), result_bits_max: a.bits, status, labels, terms, usage: {}, charged: { bits: status === "ok" ? a.bits : STATUS_BITS, epsilon: 0 },
      runtime: { remit: "0.1.0", wasmtime: "", isolation: "cloudflare-dynamic-worker" }, cached: false, attestation: null, ts: new Date().toISOString(),
    };
    const env = await this.sign(RECEIPT, jcs(receipt));
    await this.env.DB.batch([
      this.env.DB.prepare("UPDATE remit_bits SET bits = bits - ?1 WHERE day = ?2 AND scope IN (?3, '*')").bind(a.bits - receipt.charged.bits, day, `p:${m.sender}`),
      this.env.DB.prepare("INSERT INTO remit_receipt (id, body) VALUES (?1, ?2)").bind(run_id, JSON.stringify(env)),
    ]);
    return { run_id, status, result: status === "ok" ? value : null, labels, terms, provenance: { holder: this.cfg.id, remit_id: ids.remit_id, params_sha256: ids.params_sha256 }, receipt: env, usage: {}, cached: false };
  }
}

function shape(returns: any, t: { columns: Column[]; rows: any[][] }): unknown {
  const rows = t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c.name, r[i]])));
  const k = typeof returns === "string" ? returns : Object.keys(returns)[0];
  if (k === "list" || k === "table") return rows;
  if (k === "optional") return rows.length ? shape(returns.optional, t) : null;
  if (k === "struct") return rows.length === 1 ? rows[0] : rows;
  return rows.length === 1 && t.columns.length === 1 ? t.rows[0][0] : rows;
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS remit_nonce (k TEXT PRIMARY KEY, exp INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS remit_bits (scope TEXT NOT NULL, day INTEGER NOT NULL, bits INTEGER NOT NULL, PRIMARY KEY (scope, day))",
  "CREATE TABLE IF NOT EXISTS remit_receipt (id TEXT PRIMARY KEY, body TEXT NOT NULL)",
];
let ready: Promise<unknown> | null = null;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const h = new Holder(env);
    await (ready ??= env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s))));
    const url = new URL(req.url);
    const json = (v: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json", ...headers } });
    if (url.pathname === "/healthz") return new Response("ok");
    if (url.pathname === "/.well-known/remit") {
      const doc = await h.catalog([]);
      const { priv, kid } = await h.key();
      const sig = b64(new Uint8Array(await crypto.subtle.sign("Ed25519", priv, pae(CATALOG, te.encode(jcs(doc))))));
      return json(doc, 200, { etag: `"${doc.catalog_sha256}"`, "remit-signature": `keyid="${kid}", sig="${sig}"` });
    }
    const rc = /^\/remit\/v1\/receipts\/(run_[0-9a-f]+)$/.exec(url.pathname);
    if (rc) {
      const r = await env.DB.prepare("SELECT body FROM remit_receipt WHERE id = ?1").bind(rc[1]).first<{ body: string }>();
      return r ? json(JSON.parse(r.body)) : json({ error: "unknown receipt" }, 404);
    }
    if (req.method !== "POST" || !["/remit/v1/check", "/remit/v1/run"].includes(url.pathname)) return json({ error: "not found" }, 404);
    const body = await req.text();
    try {
      if (url.pathname.endsWith("/run")) return json(await h.run(body));
      const { m, groups } = await h.open(body);
      const a = await h.analyze(m, groups);
      return json({ decision: "admitted", remit_id: JSON.parse(remit_id(jcs(m))).remit_id, facts: { result_bits: a.bits } });
    } catch (e) {
      if (e instanceof Reject) return json({ decision: "rejected", status: "denied", diagnostics: e.diags }, url.pathname.endsWith("/check") ? 200 : e.denied ? 403 : 422);
      return json({ decision: "rejected", status: "internal", diagnostics: [{ code: "RMT-E0500", path: "/", message: "internal error" }] }, 500);
    }
  },
};
