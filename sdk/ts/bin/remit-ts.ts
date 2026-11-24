#!/usr/bin/env node
// remit-ts: pull | build | check | run  (TypeScript-side companion to the `remit` CLI)
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { tsImport } from "tsx/esm/api";
import { spawnSync } from "node:child_process";
import { Remit, Identity, typesDts, sqlGrammar, typecheckKernel, kernelDts, localVerifier, toJs, remitId, codeBlock, limits, toRT, capacity, capacityCeil, STATUS_BITS } from "../src/index.ts";

const [cmd, ...rest] = process.argv.slice(2);
const flag = (n: string) => {
  const i = rest.indexOf(`--${n}`);
  return i >= 0 ? rest[i + 1] : undefined;
};

async function identity() {
  return process.env.REMIT_IDENTITY || process.env.REMIT_SECRET_KEY ? Identity.fromEnv() : Identity.generate();
}

async function main() {
  switch (cmd) {
    case "pull": {
      const url = rest[0];
      const h = await new Remit({ identity: await identity() }).holder(url);
      const name = flag("name") ?? h.id.replace(/^did:web:/, "").split(".")[0];
      const dir = join(flag("dir") ?? ".remit", name);
      mkdirSync(join(dir, "examples"), { recursive: true });
      writeFileSync(join(dir, "catalog.json"), JSON.stringify(h.catalog, null, 2));
      writeFileSync(join(dir, "types.d.ts"), typesDts(h.catalog));
      writeFileSync(join(dir, "grammar.gbnf"), sqlGrammar(h.catalog));
      writeFileSync(join(dir, "stats.json"), JSON.stringify(h.catalog.stats ?? {}, null, 2));
      (h.catalog.examples ?? []).forEach((e: any, i: number) => writeFileSync(join(dir, "examples", `${String(i).padStart(2, "0")}.json`), JSON.stringify(e.manifest, null, 2)));
      console.error(`pulled ${h.id} (${h.catalogSha256}) → ${dir}`);
      break;
    }
    case "build": {
      // Kernel file: `export const remit = { reads, returns, limits, purpose }` + `export default function main`.
      const file = resolve(rest[0]);
      const imported = await tsImport(pathToFileURL(file).href, import.meta.url);
      const mod = typeof imported.default === "function" ? imported : imported.default;
      if (!mod?.remit || typeof mod.default !== "function") throw new Error("kernel files export `remit` metadata and a default `main`");
      const holder = flag("holder");
      const catFile = holder ? join(flag("dir") ?? ".remit", holder, "catalog.json") : "";
      const catalog = catFile && existsSync(catFile) ? JSON.parse(readFileSync(catFile, "utf8")) : undefined;
      if (holder && !catalog) throw new Error(`no pulled catalog at ${catFile} (run: remit-ts pull <url> --name ${holder})`);
      if (!rest.includes("--no-typecheck")) {
        const dts = kernelDts({ reads: mod.remit.reads, params: mod.remit.params, returns: toRT(mod.remit.returns), catalog, verifier: localVerifier() });
        const errs = typecheckKernel(readFileSync(file, "utf8"), dts);
        if (errs === null) console.error("note: no TypeScript compiler found; skipped type checking");
        else if (errs.length) {
          for (const e of errs) console.error(`${basename(file)}${e.span ? `:${e.span[0]}:${e.span[1]}` : ""} ${e.message}`);
          process.exit(1);
        }
      }
      const src = toJs(readFileSync(file, "utf8"));
      const m: any = {
        remit: "0.1", mode: "kernel", purpose: mod.remit.purpose ?? "unspecified",
        reads: Object.fromEntries(Object.entries<any>(mod.remit.reads).map(([k, r]) => [k, { sql: r.sql, ...(r.params ? { params: r.params } : {}), max_rows: r.max_rows ?? 1000, max_calls: r.max_calls ?? 1 }])),
        code: codeBlock(src), limits: limits(mod.remit.limits), returns: toRT(mod.remit.returns),
      };
      const id = remitId(m);
      const out = file.replace(/\.(ts|js|mts)$/, "") + ".remit.json";
      writeFileSync(out, JSON.stringify({ remit_id: id, ...m }, null, 2));
      console.error(`built ${basename(out)} (${id})`);
      break;
    }
    case "capacity": {
      const rt = JSON.parse(readFileSync(rest[0], "utf8"));
      const params = flag("params") ? JSON.parse(flag("params")!) : {};
      const bits = capacity(toRT(rt.returns ?? rt), params);
      console.log(JSON.stringify({ bits, result_bits: capacityCeil(bits) + STATUS_BITS }));
      break;
    }
    case "check":
    case "run": {
      const prog = JSON.parse(readFileSync(rest[0], "utf8"));
      const url = flag("holder")!;
      const params = flag("params") ? JSON.parse(flag("params")!) : prog.params ?? {};
      const h = await new Remit({ identity: await identity() }).holder(url);
      const body = { mode: prog.mode, reads: prog.reads, code: prog.code, params, returns: prog.returns, limits: prog.limits ?? {}, purpose: prog.purpose, authority: prog.authority };
      if (cmd === "check") {
        console.log(JSON.stringify(await h.check(body), null, 2));
      } else {
        const r = await h.run(body);
        console.log(JSON.stringify({ value: r.value, labels: r.labels, terms: r.terms, receipt: r.receipt }, null, 2));
      }
      break;
    }
    default:
      console.error("usage: remit-ts pull <url> [--name n] | build <kernel.ts> [--holder name] [--no-typecheck] | capacity <rt.json> [--params json] | check|run <x.remit.json> --holder <url> [--params json]");
      process.exit(2);
  }
}

main().catch((e) => {
  console.error(e?.message ?? e);
  if (e?.diagnostics) console.error(JSON.stringify(e.diagnostics, null, 2));
  process.exit(1);
});
