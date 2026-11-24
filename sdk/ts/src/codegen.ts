// `.d.ts` generation from a catalog (same output shape as `remit pull`).

const tsType = (t: string) => ({ bool: "boolean", int: "number", float: "number", timestamp: "Date", date: "Date" } as Record<string, string>)[t] ?? "string";
const ident = (s: string) => s.replace(/[^A-Za-z0-9]/g, "_");

/** Holder functions as a typed reference. */
export function functionsDts(catalog: any): string {
  const fns = catalog.runtime?.functions ?? [];
  return fns.map((f: any) => `/** holder.call(${JSON.stringify(f.name)}, args): ${f.description} (${f.fuel} fuel) */`).join("\n");
}

export function typesDts(catalog: any): string {
  let s = `// Generated from ${catalog.holder} (${catalog.catalog_sha256}). Do not edit.\n\n`;
  s += `export interface Table<Row> extends Iterable<Row> {\n  readonly length: number;\n  rows(): Row[];\n  col<K extends keyof Row & string>(name: K): Row[K] extends number | Date | null ? Float64Array : Array<Row[K]>;\n  map<U>(f: (r: Row, i: number) => U): U[];\n  filter(f: (r: Row, i: number) => boolean): Row[];\n  reduce<U>(f: (acc: U, r: Row, i: number) => U, init: U): U;\n}\nexport type Read<Row, P = Record<string, unknown>> = (params?: P) => Table<Row>;\n\n`;
  for (const r of catalog.resources ?? []) {
    s += `/** ${r.name}: ${JSON.stringify(r.hints ?? {})} */\nexport interface ${ident(r.name)} {\n`;
    for (const c of r.columns ?? []) {
      const ty = Array.isArray(c.enum) && c.enum.length ? c.enum.map((v: string) => JSON.stringify(v)).join(" | ") : tsType(c.type);
      s += `  ${c.name}: ${ty}${c.nullable ? " | null" : ""};\n`;
    }
    s += `}\n\n`;
  }
  const f = functionsDts(catalog);
  if (f) s += `${f}\nexport declare const holder: { call(name: string, args?: unknown): any };\n`;
  return s;
}
