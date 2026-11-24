// Remit Types (RT): builders, capacity (TS oracle), Standard Schema interop,
// and result revival (timestamps → Date, strings → Untrusted).

export type Bound = number | string; // string "$name" references a param
export type RT =
  | "bool"
  | { bool: Record<string, never> }
  | { int: { min: Bound; max: Bound } }
  | { float: { min: Bound; max: Bound; precision?: Bound } }
  | { decimal: { scale: number; min: Bound; max: Bound } }
  | { enum: string[] }
  | { string: { max_len: Bound; charset?: Charset; pattern?: string } }
  | { timestamp: { min: Bound | Date; max: Bound | Date; granularity: Bound } }
  | { date: { min: Bound; max: Bound; granularity?: Bound } }
  | { bytes: { max_len: Bound } }
  | { list: { max: Bound; of: RT } }
  | { table: { max_rows: Bound; of: RT } }
  | { struct: Record<string, RT> }
  | { optional: RT };

export type Charset = "digits" | "hex" | "alpha" | "alnum" | "base64" | "ascii" | "unicode";
const CHARSET: Record<Charset, number> = { digits: 10, hex: 22, alpha: 52, alnum: 62, base64: 67, ascii: 95, unicode: 1_112_064 };

export const STATUS_SET = ["ok", "limit_exceeded", "type_violation", "denied", "internal"] as const;
export const STATUS_BITS = Math.ceil(Math.log2(STATUS_SET.length));

const ts = (x: Bound | Date): Bound => (x instanceof Date ? x.toISOString() : x);

/** Builders for bounded result types. */
export const t = {
  bool: (): RT => "bool",
  int: (o: { min: Bound; max: Bound }): RT => ({ int: o }),
  float: (o: { min: Bound; max: Bound; precision?: Bound }): RT => ({ float: o }),
  decimal: (o: { scale: number; min: Bound; max: Bound }): RT => ({ decimal: o }),
  enum: (...values: string[]): RT => ({ enum: values.flat() }),
  string: (o: { max_len: Bound; charset?: Charset; pattern?: string }): RT => ({ string: o }),
  timestamp: (o: { min?: Bound | Date; max?: Bound | Date; granularity: Bound }): RT => ({
    timestamp: { min: ts(o.min ?? "$from"), max: ts(o.max ?? "$until"), granularity: o.granularity },
  }),
  date: (o: { min: Bound; max: Bound; granularity?: Bound }): RT => ({ date: o }),
  bytes: (o: { max_len: Bound }): RT => ({ bytes: o }),
  list: (of: RT, o: { max: Bound }): RT => ({ list: { max: o.max, of } }),
  table: (of: RT, o: { max_rows: Bound }): RT => ({ table: { max_rows: o.max_rows, of } }),
  struct: (fields: Record<string, RT>): RT => ({ struct: fields }),
  optional: (of: RT): RT => ({ optional: of }),
  /** A typed read-template param placeholder for `holder.sql\`…\``. */
  param: (name: string, type?: ParamType): ParamRef => ({ __remitParam: name, type }),
};

export type ParamType = "timestamp" | "date" | "int" | "float" | "string" | "bool";
export interface ParamRef {
  __remitParam: string;
  type?: ParamType;
}

export class RemitTypeError extends Error {
  code: string;
  path: string;
  constructor(code: string, path: string, message: string) {
    super(`${code} at ${path}: ${message}`);
    this.code = code;
    this.path = path;
  }
}

// ---------------------------------------------------------------- binding

export type Bound_ = { kind: string; [k: string]: unknown };

const MAX_TIME_MS = 8.64e15;
const MAX_LEN = 1 << 24;

function parseDuration(s: unknown, path = "/"): number {
  const bad = () => new RemitTypeError("RMT-E0107", path, `bad duration ${String(s)}`);
  if (typeof s === "number") {
    if (!Number.isInteger(s) || s <= 0 || s > MAX_TIME_MS) throw bad();
    return s;
  }
  if (typeof s !== "string") throw bad();
  let total = 0;
  const t = s.trim();
  const re = /(\d+(?:\.\d*)?|\.\d+)(ms|s|min|m|h|d|w)/gy;
  let m: RegExpExecArray | null;
  let consumed = 0;
  while ((m = re.exec(t))) {
    const mult = { ms: 1, s: 1e3, m: 6e4, min: 6e4, h: 36e5, d: 864e5, w: 6048e5 }[m[2] as "ms"];
    total += Math.round(Number(m[1]) * mult);
    consumed = re.lastIndex;
  }
  if (consumed !== t.length || consumed === 0 || total <= 0 || total > MAX_TIME_MS) throw bad();
  return total;
}

function resolve(b: Bound | Date | undefined, params: Record<string, unknown>, path: string, field: string): unknown {
  if (b === undefined || b === null) throw new RemitTypeError("RMT-E0101", `${path}/${field}`, `\`${field}\` is required: every Remit Type must be bounded`);
  if (b instanceof Date) return b.toISOString();
  if (typeof b === "string" && b.startsWith("$")) {
    const v = params[b.slice(1)];
    if (v === undefined) throw new RemitTypeError("RMT-E0104", `${path}/${field}`, `bound references param \`${b}\`, which is not provided`);
    return v instanceof Date ? v.toISOString() : v;
  }
  return b;
}

/** RFC 3339 (or the naive forms the Rust parser accepts) to epoch ms. */
function tsms(v: unknown, path: string, field: string): number {
  let t = Number.NaN;
  if (typeof v === "number" && Number.isInteger(v)) t = v;
  else if (typeof v === "string" && /^\d{4}-\d\d-\d\d([Tt ]\d\d:\d\d:\d\d(\.\d+)?([Zz]|[+-]\d\d:\d\d)?)?$/.test(v)) {
    t = Date.parse(/([Zz]|[+-]\d\d:\d\d)$/.test(v) || v.length === 10 ? v.replace(" ", "T") : `${v.replace(" ", "T")}Z`);
    // Date.parse rolls 2026-02-30 over in some engines; require a real day.
    if (!realDay(v.slice(0, 10))) t = Number.NaN;
  }
  if (!Number.isFinite(t) || Math.abs(t) > MAX_TIME_MS) throw new RemitTypeError("RMT-E0103", `${path}/${field}`, `\`${field}\` must be an RFC 3339 timestamp or epoch ms`);
  return t;
}

function realDay(s: string): boolean {
  const [y, m, d] = s.split("-").map(Number);
  return m >= 1 && m <= 12 && d >= 1 && d <= new Date(Date.UTC(y, m, 0)).getUTCDate();
}
const log2c = (n: number) => (n <= 1 ? 0 : Math.log2(n));

/** Capacity in bits of `rt` bound with `params` (the TS oracle; must agree with Rust). */
export function capacity(rt: RT, params: Record<string, unknown> = {}, path = ""): number {
  const bits = capacityInner(rt, params, path);
  if (!Number.isFinite(bits) || bits >= 2 ** 64) throw new RemitTypeError("RMT-E0130", path || "/", "result capacity exceeds the supported range");
  return bits;
}

function capacityInner(rt: RT, params: Record<string, unknown>, path: string): number {
  if (rt === "bool") return 1;
  if (typeof rt === "string") {
    const bounded = ["int", "float", "string", "list", "timestamp", "bytes", "decimal", "date"].includes(rt);
    throw new RemitTypeError(bounded ? "RMT-E0101" : "RMT-E0102", path || "/", `type \`${rt}\` needs constraints`);
  }
  const range = (lo: number, hi: number) => {
    if (lo > hi) throw new RemitTypeError("RMT-E0105", path || "/", `empty range: min ${lo} > max ${hi}`);
  };
  if (rt === null || typeof rt !== "object" || Array.isArray(rt) || Object.keys(rt).length !== 1) throw new RemitTypeError("RMT-E0102", path || "/", "a type is `\"bool\"` or a single-key object");
  const [k, b] = Object.entries(rt)[0] as [string, any];
  const p = `${path}/${k}`;
  const bad = (f: string, what: string) => new RemitTypeError("RMT-E0103", `${p}/${f}`, `\`${f}\` must be ${what}`);
  const isBody = b !== null && typeof b === "object" && !Array.isArray(b);
  if (!["bool", "enum", "optional"].includes(k) && !isBody) {
    if (["int", "float", "decimal", "string", "timestamp", "date", "bytes", "list", "table", "struct"].includes(k)) throw new RemitTypeError("RMT-E0103", p, `\`${k}\` expects an object of constraints`);
  }
  const r = (f: string) => resolve(b?.[f], params, p, f);
  const int = (f: string) => {
    const v = r(f);
    if (typeof v !== "number" || !Number.isInteger(v) || Math.abs(v) > 2 ** 63) throw bad(f, "an integer");
    return v;
  };
  const real = (f: string) => {
    const v = r(f);
    if (typeof v !== "number" || !Number.isFinite(v)) throw bad(f, "a finite number");
    return v;
  };
  const len = (f: string) => {
    const v = r(f);
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0) throw bad(f, "a non-negative integer");
    if (v > MAX_LEN) throw new RemitTypeError("RMT-E0106", `${p}/${f}`, `\`${f}\` exceeds ${MAX_LEN}`);
    return v;
  };
  const absent = (x: unknown) => x === undefined || x === null;
  switch (k) {
    case "bool":
      return 1;
    case "int": {
      const lo = int("min"), hi = int("max");
      range(lo, hi);
      return log2c(hi - lo + 1);
    }
    case "float": {
      const lo = real("min"), hi = real("max");
      range(lo, hi);
      if (absent(b.precision)) return 64;
      const pr = real("precision");
      if (pr <= 0) throw bad("precision", "> 0");
      return log2c(Math.floor((hi - lo) / pr + 1e-9) + 1);
    }
    case "decimal": {
      if (!Number.isInteger(b.scale) || b.scale < 0 || b.scale > 18) throw new RemitTypeError("RMT-E0101", `${p}/scale`, "`scale` (0..=18) is required");
      const lo = real("min"), hi = real("max");
      range(lo, hi);
      return log2c(Math.round((hi - lo) * 10 ** b.scale) + 1);
    }
    case "enum": {
      const vals = Array.isArray(b) ? b : isBody ? b.values : undefined;
      if (!Array.isArray(vals)) throw new RemitTypeError("RMT-E0101", p, "`enum` needs a list of values");
      if (vals.some((v) => typeof v !== "string") || new Set(vals).size !== vals.length) throw new RemitTypeError("RMT-E0103", p, "enum values must be distinct strings");
      if (vals.length < 1 || vals.length > 65536) throw new RemitTypeError("RMT-E0106", p, "enum must have 1..=65536 values");
      return log2c(vals.length);
    }
    case "string": {
      const cs = b.charset === undefined ? "unicode" : b.charset;
      if (typeof cs !== "string" || !Object.hasOwn(CHARSET, cs)) throw bad("charset", `one of ${Object.keys(CHARSET).join("|")}`);
      if (b.pattern !== undefined && typeof b.pattern !== "string") throw bad("pattern", "a string");
      const l = len("max_len");
      return l * Math.log2(CHARSET[cs as Charset]) + Math.log2(l + 1);
    }
    case "timestamp": {
      const lo = tsms(r("min"), p, "min"), hi = tsms(r("max"), p, "max");
      range(lo, hi);
      const g = parseDuration(r("granularity"), `${p}/granularity`);
      return log2c(Math.trunc((hi - lo) / g) + 1);
    }
    case "date": {
      const day = (f: string) => {
        const v = r(f);
        if (typeof v !== "string" || !/^\d{4}-\d\d-\d\d$/.test(v) || !realDay(v)) throw bad(f, "YYYY-MM-DD");
        return Date.parse(v) / 864e5;
      };
      const lo = day("min"), hi = day("max");
      range(lo, hi);
      let g = 1;
      if (!absent(b.granularity)) {
        const ms = parseDuration(resolve(b.granularity, params, p, "granularity"), `${p}/granularity`);
        if (ms % 864e5 !== 0 || ms / 864e5 > 2147483647) throw new RemitTypeError("RMT-E0107", `${p}/granularity`, "date granularity must be whole days");
        g = ms / 864e5;
      }
      return log2c(Math.trunc((hi - lo) / g) + 1);
    }
    case "bytes": {
      const l = len("max_len");
      return 8 * l + Math.log2(l + 1);
    }
    case "list":
    case "table": {
      if (b.of === undefined) throw new RemitTypeError("RMT-E0101", `${p}/of`, `\`${k}\` needs \`of\``);
      if (k === "table" && !(b.of && typeof b.of === "object" && "struct" in b.of)) throw bad("of", "a `struct`");
      const of = capacity(b.of, params, `${p}/of`);
      const m = len(k === "list" ? "max" : "max_rows");
      return Math.log2(m + 1) + m * of;
    }
    case "struct":
      if (Object.keys(b).some((f) => f.length === 0 || new TextEncoder().encode(f).length > 128)) throw new RemitTypeError("RMT-E0103", p, "struct field names must be 1..=128 bytes");
      return Object.entries(b as Record<string, RT>).reduce((s, [f, ft]) => s + capacity(ft, params, `${p}/${f}`), 0);
    case "optional": {
      const c = capacity(b, params, p);
      return c + Math.log2(1 + 2 ** -c);
    }
    default:
      throw new RemitTypeError("RMT-E0102", path || "/", `unknown type \`${k}\``);
  }
}

export const capacityCeil = (bits: number) => Math.max(0, Math.ceil(bits - 1e-9));

// ------------------------------------------------- Standard Schema interop

/** Anything with a Standard Schema / JSON Schema surface (Zod 4, Valibot, ArkType). */
export type SchemaLike = RT | { "~standard": unknown } | Record<string, unknown>;

/** Convert a schema library object or JSON Schema to RT JSON. */
export function toRT(s: SchemaLike): RT {
  if (s === "bool") return s;
  const anyS = s as any;
  if (anyS && typeof anyS === "object" && Object.keys(anyS).length === 1 && ["bool", "int", "float", "decimal", "enum", "string", "bytes", "timestamp", "date", "list", "table", "struct", "optional"].includes(Object.keys(anyS)[0])) {
    return anyS as RT; // already RT
  }
  let js: any = anyS;
  if (anyS["~standard"]) {
    // Standard JSON Schema (`~standard.jsonSchema.output`) or zod's toJSONSchema.
    const std = anyS["~standard"];
    if (std.jsonSchema?.output) js = std.jsonSchema.output({ target: "draft-2020-12" });
    else if (typeof anyS.toJSONSchema === "function") js = anyS.toJSONSchema();
    else if (std.vendor === "zod") js = (globalThis as any).__remitZodToJSONSchema?.(anyS);
    if (!js || js === anyS) throw new RemitTypeError("RMT-E0102", "/returns", "schema library object has no JSON Schema export (use Zod ≥ 4.2, Valibot ≥ 1.2, ArkType ≥ 2.1.28, or t.*)");
  }
  return fromJsonSchema(js, "");
}

function fromJsonSchema(s: any, path: string): RT {
  const alts = s.anyOf ?? s.oneOf;
  if (Array.isArray(alts)) {
    const nn = alts.filter((a: any) => a.type !== "null");
    if (nn.length === 1 && alts.length === 2) return { optional: fromJsonSchema(nn[0], path) };
    throw new RemitTypeError("RMT-E0102", path || "/", "unions are only supported as T | null");
  }
  if (Array.isArray(s.enum)) return { enum: s.enum.map(String) };
  if (typeof s.const === "string") return { enum: [s.const] };
  let type = s.type;
  if (Array.isArray(type)) {
    const nn = type.filter((x: string) => x !== "null");
    if (nn.length === 1 && type.length === 2) return { optional: fromJsonSchema({ ...s, type: nn[0] }, path) };
  }
  const need = (k: string, alt?: string) => {
    const v = s[k] ?? (alt ? s[alt] : undefined);
    if (v === undefined) throw new RemitTypeError("RMT-E0101", path || "/", `schema is unbounded: add \`${k}\``);
    return v;
  };
  switch (type) {
    case "boolean":
      return "bool";
    case "integer":
      return { int: { min: need("minimum", "x-remit-minimum"), max: need("maximum", "x-remit-maximum") } };
    case "number": {
      const precision = s["x-remit-precision"] ?? s.multipleOf;
      return { float: { min: need("minimum", "x-remit-minimum"), max: need("maximum", "x-remit-maximum"), ...(precision !== undefined ? { precision } : {}) } };
    }
    case "string":
      if (s.format === "decimal") return { decimal: { scale: need("x-remit-scale"), min: need("x-remit-minimum"), max: need("x-remit-maximum") } };
      if (s.format === "date-time") return { timestamp: { min: need("x-remit-minimum", "formatMinimum"), max: need("x-remit-maximum", "formatMaximum"), granularity: need("x-remit-granularity") } };
      if (s.format === "date") return { date: { min: need("x-remit-minimum"), max: need("x-remit-maximum"), ...(s["x-remit-granularity"] ? { granularity: s["x-remit-granularity"] } : {}) } };
      if (s.contentEncoding === "base64") return { bytes: { max_len: need("x-remit-maxBytes") } };
      return { string: { max_len: need("maxLength"), ...(s["x-remit-charset"] ? { charset: s["x-remit-charset"] } : {}), ...(s.pattern ? { pattern: String(s.pattern).replace(/^\^|\$$/g, "") } : {}) } };
    case "array": {
      const of = fromJsonSchema(need("items"), `${path}/items`);
      return s["x-remit-table"] ? { table: { max_rows: need("maxItems"), of } } : { list: { max: need("maxItems"), of } };
    }
    case "object": {
      const req = new Set<string>(s.required ?? []);
      const fields: Record<string, RT> = {};
      for (const [k, ps] of Object.entries(s.properties ?? {})) {
        const ft = fromJsonSchema(ps, `${path}/properties/${k}`);
        fields[k] = req.has(k) || (typeof ft === "object" && "optional" in ft) ? ft : { optional: ft };
      }
      return { struct: fields };
    }
    default:
      throw new RemitTypeError("RMT-E0102", path || "/", `unsupported schema type \`${type}\``);
  }
}

/** TypeScript rendering of an RT (for generated kernel signatures). */
export function toTs(rt: RT): string {
  if (rt === "bool") return "boolean";
  const [k, b] = Object.entries(rt)[0] as [string, any];
  switch (k) {
    case "bool": return "boolean";
    case "int": case "float": return "number";
    case "decimal": case "string": case "bytes": return "string";
    case "enum": return (Array.isArray(b) ? b : b.values).map((v: string) => JSON.stringify(v)).join(" | ");
    case "timestamp": case "date": return "Date";
    case "list": case "table": return `Array<${toTs(b.of)}>`;
    case "optional": return `${toTs(b)} | null`;
    case "struct": return `{ ${Object.entries(b as Record<string, RT>).map(([f, ft]) => `${/^[A-Za-z_$][\w$]*$/.test(f) ? f : JSON.stringify(f)}: ${toTs(ft)}`).join("; ")} }`;
  }
  return "unknown";
}

// -------------------------------------------------------------- revival

/**
 * Values from another agent's data are data, not instructions. Strings come
 * back wrapped so agent frameworks keep them out of the instruction stream.
 */
export class Untrusted<T = string> {
  readonly value: T;
  readonly source: { holder: string; remit_id: string };
  constructor(value: T, source: { holder: string; remit_id: string }) {
    this.value = value;
    this.source = source;
    Object.freeze(this);
  }
  /** Explicitly unwrap for use as *data* (e.g. display, comparison). */
  unwrap(): T {
    return this.value;
  }
  toString(): string {
    return `[Untrusted from ${this.source.holder}]`;
  }
  toJSON() {
    return { untrusted: this.value, holder: this.source.holder };
  }
}

/** Revive a JSON result using its type: timestamps → Date, strings → Untrusted. */
export function revive(rt: RT, v: unknown, src: { holder: string; remit_id: string }, wrapStrings = true): unknown {
  if (v === null || v === undefined) return v ?? null;
  if (rt === "bool") return v;
  const [k, b] = Object.entries(rt)[0] as [string, any];
  switch (k) {
    case "timestamp": case "date": return new Date(v as string);
    case "string": return wrapStrings ? new Untrusted(v as string, src) : v;
    case "list": case "table": return (v as unknown[]).map((x) => revive(b.of, x, src, wrapStrings));
    case "optional": return revive(b, v, src, wrapStrings);
    case "struct": {
      const out: Record<string, unknown> = {};
      for (const [f, ft] of Object.entries(b as Record<string, RT>)) out[f] = revive(ft, (v as any)[f], src, wrapStrings);
      return out;
    }
    default: return v;
  }
}
