// TS Holder bindings: expose in-process data as Remit resources. Each resource
// is a function returning rows; `EmbeddedHolder` snapshots them, supervises a
// `remit serve` sidecar (the trusted Rust Holder) and refreshes on demand.

import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Identity } from "./identity.ts";

export interface EmbeddedResource {
  /** Current rows (plain objects; Dates allowed). */
  rows: () => Record<string, unknown>[] | Promise<Record<string, unknown>[]>;
  /** `[catalog."source.table"]` options (aggregate_only, k, columns, purposes, dp, …). */
  config?: Record<string, unknown>;
}

export interface EmbeddedHolderOptions {
  id: string;
  identity: Identity;
  /** `source.table` → resource. */
  resources: Record<string, EmbeddedResource>;
  presets?: string[];
  /** Extra Cedar policy text. */
  policy?: string;
  principals?: { id: string; keys?: string[]; groups?: string[]; verified?: boolean }[];
  budgets?: Record<string, unknown>;
  /** `remit` binary (default: `remit` on PATH, or $REMIT_BIN). */
  bin?: string;
  engine?: string;
  isolation?: "process" | "inprocess";
  listen?: string;
}

/** Minimal TOML writer for the values used here. */
function toml(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(toml).join(", ")}]`;
  if (v && typeof v === "object") return `{ ${Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => `${JSON.stringify(k)} = ${toml(x)}`).join(", ")} }`;
  return JSON.stringify(v);
}

export class EmbeddedHolder {
  readonly url: string;
  readonly #dir: string;
  readonly #o: EmbeddedHolderOptions;
  readonly #token: string;
  #child: ChildProcess | null = null;

  private constructor(o: EmbeddedHolderOptions, dir: string, url: string, token: string) {
    this.#o = o;
    this.#dir = dir;
    this.url = url;
    this.#token = token;
  }

  static async start(o: EmbeddedHolderOptions): Promise<EmbeddedHolder> {
    const dir = mkdtempSync(join(tmpdir(), "remit-embedded-"));
    const listen = o.listen ?? `127.0.0.1:${await freePort()}`;
    const token = randomBytes(16).toString("hex");
    const h = new EmbeddedHolder(o, dir, `http://${listen}`, token);
    try {
      await h.#snapshot();
      writeFileSync(join(dir, "identity.json"), JSON.stringify({ ...o.identity.toJSON(), id: o.id }), { mode: 0o600 });
      if (o.policy) writeFileSync(join(dir, "policy.cedar"), o.policy);
      let t = `[holder]\nid = ${toml(o.id)}\nlisten = ${toml(listen)}\nisolation = ${toml(o.isolation ?? "process")}\nidentity = "identity.json"\nadmin_token = ${toml(token)}\n\n`;
      t += `[policy]\npresets = ${toml(o.presets ?? ["personal-vault"])}\nfiles = ${toml(o.policy ? ["policy.cedar"] : [])}\n\n`;
      if (o.budgets) t += `[budgets]\n${Object.entries(o.budgets).map(([k, v]) => `${k} = ${toml(v)}`).join("\n")}\n\n`;
      if (o.engine) t += `[runtime]\nengine = ${toml(o.engine)}\n\n`;
      for (const [name, r] of Object.entries(o.resources)) {
        const [src, table] = name.split(".");
        if (!src || !table) throw new Error(`resource names are source.table, got ${name}`);
        t += `[[source]]\nname = ${toml(src)}\nkind = "json"\npath = ${toml(`data/${name}.ndjson`)}\ntable = ${toml(table)}\n\n`;
        if (r.config) t += `[catalog.${toml(name)}]\n${Object.entries(r.config).map(([k, v]) => `${k} = ${toml(v)}`).join("\n")}\n\n`;
      }
      for (const p of o.principals ?? []) t += `[[principal]]\n${Object.entries(p).map(([k, v]) => `${k} = ${toml(v)}`).join("\n")}\n\n`;
      writeFileSync(join(dir, "remit.toml"), t);
      await h.#spawn();
      return h;
    } catch (e) {
      h.stop();
      throw e;
    }
  }

  /** Write every resource's rows (atomically) as the next snapshot. */
  async #snapshot() {
    mkdirSync(join(this.#dir, "data"), { recursive: true });
    for (const [name, r] of Object.entries(this.#o.resources)) {
      const rows = await r.rows();
      if (!rows.length) throw new Error(`resource ${name} returned no rows (its schema cannot be inferred)`);
      const p = join(this.#dir, "data", `${name}.ndjson`);
      writeFileSync(`${p}.tmp`, rows.map((x) => JSON.stringify(x)).join("\n") + "\n");
      renameSync(`${p}.tmp`, p);
    }
  }

  async #spawn() {
    const child = spawn(this.#o.bin ?? process.env.REMIT_BIN ?? "remit", ["serve", "--config", join(this.#dir, "remit.toml")], { stdio: ["ignore", "ignore", "pipe"] });
    this.#child = child;
    let log = "";
    child.stderr!.on("data", (d) => (log = (log + d).slice(-4000)));
    let exited: string | null = null;
    child.on("error", (e) => (exited = String(e)));
    child.on("exit", (c) => (exited ??= `exited with ${c}`));
    for (let i = 0; i < 600; i++) {
      if (exited) throw new Error(`remit serve failed: ${exited}\n${log}`);
      try {
        if ((await fetch(`${this.url}/healthz`)).ok) return;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`remit serve did not become ready\n${log}`);
  }

  /** Re-read every resource and pin a new snapshot. */
  async refresh() {
    await this.#snapshot();
    const r = await fetch(`${this.url}/admin/refresh`, { method: "POST", headers: { authorization: `Bearer ${this.#token}` } });
    if (!r.ok) throw new Error(`refresh failed: ${r.status} ${await r.text()}`);
  }

  async approvals(): Promise<any> {
    return (await fetch(`${this.url}/admin/approvals`, { headers: { authorization: `Bearer ${this.#token}` } })).json();
  }

  stop() {
    this.#child?.kill();
    this.#child = null;
    rmSync(this.#dir, { recursive: true, force: true });
  }
}

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.on("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as any).port;
      s.close(() => res(p));
    });
  });
}
