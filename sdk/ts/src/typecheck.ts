// Type-check kernels against types generated from the catalog: `Reads` (row
// types inferred by binding each read's SQL), `Params` and `Result` (the
// declared bounded type). Runs in-process on the TypeScript compiler API when
// it is installed (`typescript` ≤ 6, or `@typescript/typescript6`), otherwise
// through a `tsc` binary (TypeScript 7).

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Diagnostic } from "./client.ts";
import type { ReadTemplate } from "./manifest.ts";
import { type ParamType, type RT, toTs } from "./types.ts";
import type { Verifier } from "./verifier.ts";

const TS: Record<string, string> = { bool: "boolean", int: "number", float: "number", timestamp: "Date", date: "Date", string: "string", bytes: "Uint8Array" };

export const TABLE_DTS = `
interface RemitTable<Row> extends Iterable<Row> {
  readonly length: number;
  readonly schema: ReadonlyArray<{ name: string; type: string }>;
  rows(): Row[];
  col<K extends keyof Row & string>(name: K): NonNullable<Row[K]> extends number | Date ? Float64Array : Array<Row[K]>;
  map<U>(f: (r: Row, i: number) => U): U[];
  filter(f: (r: Row, i: number) => boolean): Row[];
  reduce<U>(f: (acc: U, r: Row, i: number) => U, init: U): U;
  forEach(f: (r: Row, i: number) => void): void;
  some(f: (r: Row) => boolean): boolean;
  every(f: (r: Row) => boolean): boolean;
  find(f: (r: Row) => boolean): Row | undefined;
  slice(a?: number, b?: number): Row[];
  at(i: number): Row | undefined;
}
declare const holder: { call(name: string, args?: unknown): any };
`;

function paramTs(t: ParamType | undefined, v: unknown): string {
  if (t) return TS[t] ?? "unknown";
  if (v instanceof Date) return "Date";
  if (Array.isArray(v)) return "unknown[]";
  return v === null || v === undefined ? "unknown" : typeof v === "object" ? "Record<string, unknown>" : typeof v;
}

/** Ambient declarations for one kernel. */
export function kernelDts(o: { reads: Record<string, ReadTemplate>; params?: Record<string, unknown>; returns: RT; catalog?: unknown; verifier?: Verifier }): string {
  let s = TABLE_DTS;
  const types: Record<string, ParamType> = {};
  const reads: string[] = [];
  for (const [name, r] of Object.entries(o.reads)) {
    Object.assign(types, r.params ?? {});
    const b = o.catalog && o.verifier?.bindSql ? o.verifier.bindSql(r.sql, o.catalog) : null;
    const row = b?.ok ? `{ ${b.bound!.columns.map((c) => `${JSON.stringify(c.name)}: ${TS[c.type] ?? "any"}${c.nullable ? " | null" : ""}`).join("; ")} }` : "Record<string, any>";
    const ps = Object.entries(r.params ?? {}).map(([p, t]) => `${JSON.stringify(p)}: ${t === "timestamp" || t === "date" ? "Date | string | number" : TS[t] ?? "unknown"}`);
    reads.push(`  ${JSON.stringify(name)}: (params${ps.length ? "" : "?"}: ${ps.length ? `{ ${ps.join("; ")} }` : "object"}) => RemitTable<${row}>;`);
  }
  s += `interface Reads {\n${reads.join("\n")}\n}\n`;
  const pnames = new Set([...Object.keys(types), ...Object.keys(o.params ?? {})]);
  s += `interface Params {\n${[...pnames].map((p) => `  ${JSON.stringify(p)}: ${paramTs(types[p], o.params?.[p])};`).join("\n")}\n}\n`;
  s += `type Result = ${toTs(o.returns)};\n`;
  return s;
}

const OPTIONS = { strict: true, noEmit: true, target: "es2023", lib: ["es2023"], module: "esnext", moduleResolution: "bundler", types: [], skipLibCheck: true, noImplicitAny: false, strictNullChecks: true };

/** A check that the default export has the kernel signature. */
function signature(source: string): string {
  // A kernel that declares its own `Reads` / `Params` / `Result` makes its own
  // claims about nullability and shape; those names are then not ours to check
  // (the Holder validates the actual result either way).
  const own = (n: string) => new RegExp(`\\b(?:interface|type)\\s+${n}\\b`).test(source);
  const t = (n: string) => (own(n) ? "any" : n);
  return `\nimport __main from "./kernel.ts";\nconst __check: (reads: ${t("Reads")}, params: ${t("Params")}) => ${t("Result")} | Promise<${t("Result")}> = __main;\nvoid __check;\n`;
}

let api: any;
function compiler(): any {
  if (api !== undefined) return api;
  api = null;
  const req = createRequire(import.meta.url);
  for (const m of ["@typescript/typescript6", "typescript"]) {
    try {
      const ts = req(m);
      if (typeof ts.createProgram === "function") {
        api = ts;
        break;
      }
    } catch {
      /* not installed */
    }
  }
  return api;
}

/** Types erased by an installed TypeScript compiler, if any. */
export function transpile(source: string): string | null {
  const ts = compiler();
  if (!ts) return null;
  return ts.transpileModule(source, { compilerOptions: { target: "es2023", module: "esnext", verbatimModuleSyntax: true } }).outputText;
}

/** Diagnostics, or `null` when no TypeScript compiler is available. */
export function typecheckKernel(source: string, dts: string): Diagnostic[] | null {
  const ts = compiler();
  const files: Record<string, string> = { "/kernel.ts": source, "/remit-env.d.ts": dts, "/check.ts": signature(source) };
  if (ts) {
    const options = ts.convertCompilerOptionsFromJson({ ...OPTIONS, allowImportingTsExtensions: true }, "/").options;
    const host = ts.createCompilerHost(options);
    const orig = { getSourceFile: host.getSourceFile.bind(host), fileExists: host.fileExists.bind(host), readFile: host.readFile.bind(host) };
    host.getSourceFile = (f: string, l: any) => (f in files ? ts.createSourceFile(f, files[f], l, true) : orig.getSourceFile(f, l));
    host.fileExists = (f: string) => f in files || orig.fileExists(f);
    host.readFile = (f: string) => files[f] ?? orig.readFile(f);
    host.getCurrentDirectory = () => "/";
    host.writeFile = () => {};
    const prog = ts.createProgram(Object.keys(files), options, host);
    return ts.getPreEmitDiagnostics(prog).map((d: any) => {
      const pos = d.file && d.start !== undefined ? d.file.getLineAndCharacterOfPosition(d.start) : null;
      const inKernel = d.file?.fileName === "/kernel.ts";
      return diag(d.code, ts.flattenDiagnosticMessageText(d.messageText, " "), inKernel && pos ? [pos.line + 1, pos.character + 1] : undefined);
    });
  }
  const dir = mkdtempSync(join(tmpdir(), "remit-tsc-"));
  try {
    writeFileSync(join(dir, "kernel.ts"), source);
    writeFileSync(join(dir, "remit-env.d.ts"), dts);
    writeFileSync(join(dir, "check.ts"), signature(source));
    writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { ...OPTIONS, allowImportingTsExtensions: true }, files: ["kernel.ts", "remit-env.d.ts", "check.ts"] }));
    try {
      execFileSync(process.env.REMIT_TSC ?? "tsc", ["--noEmit", "--pretty", "false", "-p", dir], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      return [];
    } catch (e: any) {
      if (e.code === "ENOENT") return null;
      return String(e.stdout ?? "").split("\n").flatMap((l) => {
        const m = /^(?:.*?)(kernel|check)\.ts\((\d+),(\d+)\): error TS(\d+): (.*)$/.exec(l);
        return m ? [diag(Number(m[4]), m[5], m[1] === "kernel" ? [Number(m[2]), Number(m[3])] : undefined)] : [];
      });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function diag(code: number, message: string, span?: [number, number]): Diagnostic {
  return { code: "RMT-E0610", path: "/code/source", message: `TS${code}: ${message}`, ...(span ? { span } : { hint: "the default export must match (reads: Reads, params: Params) => Result" }) };
}
