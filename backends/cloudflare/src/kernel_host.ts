// The module that runs *inside* the dynamic worker, around the Sender's code.
// It has no bindings and no outbound network; clocks and randomness are
// replaced by deterministic ones before Sender code is evaluated.
export const KERNEL_HOST = `
import { __remitTables } from "./data.js";
const TIME = new Set(["timestamp", "date"]);
class Table {
  #t; #rows = null;
  constructor(t) { this.#t = t; this.length = t.rows.length; this.schema = Object.freeze(t.columns.map((c) => Object.freeze(c))); Object.freeze(this); }
  rows() {
    return (this.#rows ??= this.#t.rows.map((r) => Object.fromEntries(this.#t.columns.map((c, i) => [c.name, r[i] !== null && TIME.has(c.type) ? new Date(r[i]) : r[i]]))));
  }
  col(n) {
    const i = this.#t.columns.findIndex((c) => c.name === n);
    if (i < 0) throw new TypeError("unknown column");
    const ty = this.#t.columns[i].type, v = this.#t.rows.map((r) => r[i]);
    return ty === "int" || ty === "float" || TIME.has(ty) ? Float64Array.from(v, (x) => (x === null ? NaN : TIME.has(ty) ? Date.parse(x) : x)) : v;
  }
  [Symbol.iterator]() { return this.rows()[Symbol.iterator](); }
  map(f) { return this.rows().map(f); } filter(f) { return this.rows().filter(f); } reduce(f, i) { return this.rows().reduce(f, i); }
  forEach(f) { this.rows().forEach(f); } some(f) { return this.rows().some(f); } every(f) { return this.rows().every(f); } find(f) { return this.rows().find(f); }
  slice(a, b) { return this.rows().slice(a, b); } at(i) { return this.rows().at(i); }
}
function harden(now, seed) {
  const R = Date;
  const D = function (...a) { return new.target ? (a.length ? new R(...a) : new R(now)) : new R(now).toString(); };
  D.prototype = R.prototype; D.now = () => now; D.parse = R.parse; D.UTC = R.UTC;
  Object.defineProperty(R.prototype, "constructor", { value: D });
  globalThis.Date = D;
  let s = seed >>> 0;
  Math.random = () => { s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  for (const k of ["fetch", "setTimeout", "setInterval", "setImmediate", "caches", "WebSocket", "EventSource", "crypto", "performance", "navigator", "scheduler", "queueMicrotask", "WebAssembly"]) {
    try { Object.defineProperty(globalThis, k, { value: undefined, configurable: false }); } catch {}
  }
}
const enc = (v) => v instanceof Date ? { $d: +v } : Array.isArray(v) ? v.map(enc) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, enc(x)])) : v;
export default {
  async fetch(req) {
    const { now, seed, params, dates } = await req.json();
    harden(now, seed);
    for (const k of dates) if (typeof params[k] === "string") params[k] = new Date(Date.parse(params[k]));
    try {
      const mod = await import("./kernel.js");
      const main = typeof mod.default === "function" ? mod.default : mod.main;
      const reads = Object.freeze(Object.fromEntries(Object.entries(__remitTables).map(([n, t]) => [n, () => new Table(t)])));
      const out = await main(reads, Object.freeze(params));
      const text = JSON.stringify(enc(out === undefined ? null : out));
      return new Response(text ?? "null");
    } catch { return new Response("", { status: 500 }); }
  },
};
`;
