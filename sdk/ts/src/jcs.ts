// RFC 8785 JSON Canonicalization Scheme — independent TS implementation
// (the differential-testing oracle for the Rust normative one).

export function canonicalize(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new TypeError("non-finite number cannot be canonicalized");
      // ECMAScript Number.prototype.toString is exactly the JCS number format.
      return Object.is(v, -0) ? "0" : String(v);
    case "string":
      return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return "[" + Array.from(v, (x) => canonicalize(x === undefined ? null : x)).join(",") + "]";
      if (v instanceof Date) return JSON.stringify(v.toISOString());
      const o = v as Record<string, unknown>;
      const keys = Object.keys(o).filter((k) => o[k] !== undefined);
      // Sort by UTF-16 code units: the default JS string comparison.
      keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(o[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`cannot canonicalize ${typeof v}`);
  }
}
