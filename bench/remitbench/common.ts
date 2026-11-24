import { readFileSync, existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import type { Data } from "./tasks.ts";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const HOLDERS = {
  vault: { url: "http://127.0.0.1:8443", dir: "examples/personal-vault", key: "examples/personal-vault/keys/travel-agent.json" },
  crm: { url: "http://127.0.0.1:8444", dir: "examples/enterprise-analytics", key: "examples/enterprise-analytics/keys/finance-agent.json" },
  docs: { url: "http://127.0.0.1:8446", dir: "examples/docs-rag", key: "examples/docs-rag/keys/support-agent.json" },
  b2b: { url: "http://127.0.0.1:8445", dir: "examples/b2b-overlap", key: "examples/b2b-overlap/keys/company-a.json" },
} as const;

export function csv(path: string): any[] {
  const [head, ...lines] = readFileSync(join(ROOT, path), "utf8").trim().split(/\r?\n/);
  const cols = head.split(",");
  return lines.map((l) => Object.fromEntries(l.split(",").map((v, i) => [cols[i], v])));
}

export function loadData(): Data {
  return {
    events: csv("examples/personal-vault/data/events.csv"),
    accounts: csv("examples/enterprise-analytics/data/accounts.csv"),
    deals: csv("examples/enterprise-analytics/data/deals.csv"),
    customers: csv("examples/b2b-overlap/data/customers.csv"),
    chunks: csv("examples/docs-rag/data/chunks.csv"),
    companyA: readFileSync(join(ROOT, "examples/b2b-overlap/data/company-a-list.txt"), "utf8").trim().split("\n"),
  };
}

export const hashEmail = (e: string) => createHash("sha256").update(e.trim().toLowerCase()).digest("hex");

export function remitBin(): string {
  if (process.env.REMIT_BIN) return process.env.REMIT_BIN;
  // The most recently built binary.
  const found = ["target/release/remit", "target/debug/remit"].map((p) => join(ROOT, p)).filter((p) => existsSync(p)).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  if (found[0]) return found[0];
  throw new Error("build the CLI first: cargo build --release -p bitsinfra-remit");
}

export async function waitFor(url: string, ms = 120_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try {
      if ((await fetch(url + "/healthz")).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`holder ${url} did not start`);
}

export async function spawnHolders(): Promise<ChildProcess[]> {
  const bin = remitBin();
  // Benchmarks ask far more than the examples' daily budgets allow: run each
  // Holder from a copy of its config with larger budgets and a fresh data dir.
  const kids = Object.values(HOLDERS).map((h) => {
    const dir = join(ROOT, h.dir);
    const cfg = readFileSync(join(dir, "remit.toml"), "utf8")
      .replace(/^data_dir = .*$/m, `data_dir = ${JSON.stringify(mkdtempSync(join(tmpdir(), "remit-bench-")))}`)
      .replace(/^bits_per_principal_per_day.*$/m, "bits_per_principal_per_day = 10000000")
      .replace(/^bits_global_per_day.*$/m, "bits_global_per_day = 100000000")
      .replace(/^pad_ms.*$/gm, "")
      .replace(/^\[budgets\]$/m, "[budgets]\nfuel_per_principal_per_minute = 100000000000000\nfuel_per_principal_per_day = 100000000000000");
    const p = join(dir, ".remit.bench.toml");
    writeFileSync(p, cfg);
    const kid = spawn(bin, ["serve", "--config", p], { cwd: join(ROOT, h.dir), stdio: ["ignore", "ignore", "inherit"], env: { ...process.env, RUST_LOG: "warn" } });
    kid.on("exit", () => rmSync(p, { force: true }));
    return kid;
  });
  await Promise.all(Object.values(HOLDERS).map((h) => waitFor(h.url)));
  return kids;
}

/** MCP-tools baseline: sensible tools that return records. */
export function baselineTool(d: Data, tool: string, args: any): any[] {
  switch (tool) {
    case "list_events":
      return d.events.filter((e) => (!args.from || e.end_at > args.from) && (!args.until || e.start_at < args.until));
    case "list_accounts":
      return d.accounts.filter((a) => !args.region || a.region === args.region);
    case "list_deals":
      return d.deals.filter((x) => !args.stage || x.stage === args.stage);
    case "list_chunks":
      return d.chunks;
    case "list_customers":
      return d.customers;
  }
  throw new Error(`unknown tool ${tool}`);
}

/** Params with data references resolved (`$companyA`, `$companyA:from:to`). */
export function resolveParams(d: Data, params: Record<string, unknown> = {}): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(params).map(([k, v]) => {
      const m = typeof v === "string" ? /^\$companyA(?::(\d+):(\d+))?$/.exec(v) : null;
      return [k, m ? d.companyA.slice(Number(m[1] ?? 0), Number(m[2] ?? d.companyA.length)).map(hashEmail) : v];
    }),
  );
}

/** Bytes of the MCP JSON-RPC response carrying `rows`. */
export function mcpBytes(rows: any[], id: number): number {
  return Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(rows) }], isError: false } }));
}
