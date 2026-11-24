// Browser / worker entry: WebCrypto signing (no node:* imports) and the Rust
// verifier as Wasm. Bundle with any bundler, or import the built `dist/`.
//
//   const remit = new BrowserRemit(await WebIdentity.generate(), verifier);
//   const holder = await remit.holder("https://alice.vault.example");
//   const r = await holder.query({ sql, returns, purpose });

import { canonicalize } from "./jcs.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MANIFEST = "application/vnd.remit.manifest+json";
const RECEIPT = "application/vnd.remit.receipt+json";
const CATALOG = "application/vnd.remit.catalog+json";

type Bytes = Uint8Array<ArrayBuffer>;

function b58encode(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  for (; n > 0n; n /= 58n) s = B58[Number(n % 58n)] + s;
  for (const x of b) {
    if (x) break;
    s = "1" + s;
  }
  return s;
}

function b58decode(s: string): Bytes {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("invalid base58");
    n = n * 58n + BigInt(i);
  }
  const out: number[] = [];
  for (; n > 0n; n >>= 8n) out.unshift(Number(n & 255n));
  return Uint8Array.from(out);
}

const b64 = (b: Uint8Array) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
const unb64 = (s: string): Bytes => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
export const sha256 = async (s: string) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));

function pae(type: string, body: Uint8Array): Bytes {
  const head = enc.encode(`DSSEv1 ${enc.encode(type).length} ${type} ${body.length} `);
  const out = new Uint8Array(head.length + body.length);
  out.set(head);
  out.set(body, head.length);
  return out;
}

async function verify(didKey: string, msg: Bytes, sig: Bytes): Promise<boolean> {
  const b = b58decode(didKey.split("#")[0].slice("did:key:z".length));
  if (b[0] === 0xed && b[1] === 1) {
    const k = await crypto.subtle.importKey("raw", b.slice(2), "Ed25519", false, ["verify"]);
    return crypto.subtle.verify("Ed25519", k, sig, msg);
  }
  throw new Error("only Ed25519 Holder keys are supported in the browser entry");
}

/** An Ed25519 identity held by WebCrypto (the private key is not extractable). */
export class WebIdentity {
  readonly didKey: string;
  readonly #key: CryptoKey;
  private constructor(key: CryptoKey, didKey: string) {
    this.#key = key;
    this.didKey = didKey;
  }
  static async generate(): Promise<WebIdentity> {
    const kp = (await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return new WebIdentity(kp.privateKey, "did:key:z" + b58encode(Uint8Array.from([0xed, 1, ...raw])));
  }
  async sign(msg: Bytes): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.sign("Ed25519", this.#key, msg));
  }
}

export interface BrowserVerifier {
  check_sql(sql: string): string;
  validate(returns: string, params: string, value: string): string;
  capacity(returns: string, params: string): string;
  remit_id(manifest: string): string;
}

export class BrowserRemit {
  readonly identity: WebIdentity;
  readonly verifier: BrowserVerifier | null;
  constructor(identity: WebIdentity, verifier: BrowserVerifier | null = null) {
    this.identity = identity;
    this.verifier = verifier;
  }
  async holder(url: string, pin?: string): Promise<BrowserHolder> {
    const base = url.replace(/\/$/, "");
    const r = await fetch(`${base}/.well-known/remit`);
    const catalog = await r.json();
    const sig = /sig="([^"]+)"/.exec(r.headers.get("remit-signature") ?? "")?.[1];
    const key: string = catalog.keys[0].did_key;
    if (pin && pin !== key) throw new Error("catalog key does not match the pinned key");
    if (!sig || !(await verify(key, pae(CATALOG, enc.encode(canonicalize(catalog))), unb64(sig)))) throw new Error("catalog signature does not verify");
    return new BrowserHolder(this, base, catalog);
  }
}

export interface BrowserProgram {
  sql?: string;
  reads?: Record<string, { sql: string; params?: Record<string, string>; max_rows: number; max_calls?: number }>;
  source?: string;
  params?: Record<string, unknown>;
  returns: unknown;
  limits?: Record<string, unknown>;
  purpose: string;
}

export class BrowserHolder {
  readonly remit: BrowserRemit;
  readonly url: string;
  readonly catalog: any;
  constructor(remit: BrowserRemit, url: string, catalog: any) {
    this.remit = remit;
    this.url = url;
    this.catalog = catalog;
  }

  async envelope(p: BrowserProgram): Promise<any> {
    const now = Date.now();
    const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
    const params = Object.fromEntries(Object.entries(p.params ?? {}).map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v]));
    const types = Object.fromEntries([...p.sql?.matchAll(/\$([A-Za-z_]\w*)/g) ?? []].map((m) => {
      const v = p.params?.[m[1]];
      return [m[1], v instanceof Date || typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v) ? "timestamp" : typeof v === "boolean" ? "bool" : typeof v === "number" ? Number.isInteger(v) ? "int" : "float" : "string"];
    }));
    const reads = Object.fromEntries(Object.entries(p.reads ?? { q: { sql: p.sql!, params: types, max_rows: 1000 } }).map(([k, r]) => [k, { ...r, max_calls: r.max_calls ?? 1 }]));
    const m: any = {
      remit: "0.1", sender: this.remit.identity.didKey, holder: this.catalog.holder, issued_at: iso(now), expires_at: iso(now + 300_000),
      nonce: hex(crypto.getRandomValues(new Uint8Array(16)).buffer), purpose: p.purpose, mode: p.source ? "kernel" : "query", reads, params, limits: p.limits ?? {}, returns: p.returns,
    };
    if (p.source) m.code = { lang: "js/es2023", entry: "main", source: p.source, source_sha256: await sha256(p.source) };
    const body = enc.encode(canonicalize(m));
    return { payloadType: MANIFEST, payload: b64(body), signatures: [{ keyid: this.remit.identity.didKey, sig: b64(await this.remit.identity.sign(pae(MANIFEST, body))) }] };
  }

  async check(p: BrowserProgram): Promise<any> {
    return (await fetch(`${this.url}/remit/v1/check`, { method: "POST", body: JSON.stringify(await this.envelope(p)) })).json();
  }

  async run(p: BrowserProgram): Promise<{ value: unknown; receipt: any; response: any }> {
    if (!this.remit.verifier) throw new Error("a BrowserVerifier is required to run a program");
    const env = await this.envelope(p);
    const manifest = JSON.parse(dec.decode(unb64(env.payload)));
    const ids = JSON.parse(this.remit.verifier.remit_id(JSON.stringify(manifest)));
    const r = await (await fetch(`${this.url}/remit/v1/run`, { method: "POST", body: JSON.stringify(env) })).json();
    if (r.status !== "ok") throw Object.assign(new Error(r.decision ?? r.status), { response: r });
    const body = unb64(r.receipt.payload);
    if (r.receipt.payloadType !== RECEIPT || !(await verify(this.catalog.keys[0].did_key, pae(RECEIPT, body), unb64(r.receipt.signatures[0].sig)))) throw new Error("receipt signature does not verify");
    const receipt = JSON.parse(dec.decode(body));
    if (receipt.status !== "ok" || receipt.decision !== "admitted" || receipt.remit_id !== ids.remit_id || receipt.params_sha256 !== ids.params_sha256 || receipt.sender !== manifest.sender || receipt.holder !== manifest.holder) throw new Error("receipt does not match the submitted remit");
    if (receipt.result_sha256 !== `sha256:${await sha256(canonicalize(r.result))}`) throw new Error("result does not match the signed receipt");
    const v = this.remit.verifier && JSON.parse(this.remit.verifier.validate(JSON.stringify(p.returns), JSON.stringify(p.params ?? {}), JSON.stringify(r.result)));
    if (!v?.ok || canonicalize(v.value) !== canonicalize(r.result)) throw new Error(`result does not inhabit the declared type: ${v?.error ?? "non-canonical value"}`);
    return { value: r.result, receipt, response: { ...r, labels: receipt.labels, terms: receipt.terms } };
  }

  query(p: BrowserProgram) {
    return this.run(p);
  }
  kernel(p: BrowserProgram) {
    return this.run(p);
  }
}
