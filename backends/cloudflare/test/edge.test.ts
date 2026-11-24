// The edge Holder under workerd (Miniflare), driven by the real TS SDK.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Miniflare } from "miniflare";
import { bind, codeBlock, Identity, Remit, RemitError, signManifest, t } from "../../../sdk/ts/src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
let mf: Miniflare, url: string;
const sender = Identity.generate("did:web:agent.example");
const CONFIG = {
  id: "did:web:edge.example",
  resources: {
    "calendar.events": { view: "v_events", labels: ["personal", "no-forward"], retain_days: 30, purposes: ["scheduling"], max_bits: 128, columns: [{ name: "id", type: "int" }, { name: "start_at", type: "timestamp" }, { name: "end_at", type: "timestamp" }, { name: "busy", type: "bool" }] },
    "crm.accounts": { view: "v_accounts", aggregate_only: true, columns: [{ name: "region", type: "string" }, { name: "arr", type: "float" }] },
    "hr.salaries": { view: "v_salaries", groups: ["hr"], columns: [{ name: "x", type: "int" }] },
  },
  principals: { [sender.id]: { keys: [sender.didKey], groups: ["verified-agents"] } },
  limits: { wall_ms: 1500, cpu_ms: 1000 },
  budgets: { bits_per_principal_per_day: 2000 },
};

before(async () => {
  const worker = readFileSync(join(here, "../dist/worker.js"), "utf8");
  const wasm = readFileSync(join(here, "../dist/remit_verify_wasm_bg.wasm"));
  const key = generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  mf = new Miniflare({
    modules: [{ type: "ESModule", path: "worker.js", contents: worker }, { type: "CompiledWasm", path: "remit_verify_wasm_bg.wasm", contents: wasm }],
    compatibilityDate: "2026-01-01",
    d1Databases: ["DB"],
    workerLoaders: { LOADER: {} },
    bindings: { REMIT_CONFIG: JSON.stringify(CONFIG), REMIT_KEY: key },
  });
  url = (await mf.ready).toString().replace(/\/$/, "");
  const db = await mf.getD1Database("DB");
  for (const s of [
    "CREATE TABLE events (id INTEGER, start_at TEXT, end_at TEXT, busy INTEGER, title TEXT)",
    "INSERT INTO events VALUES (1,'2026-11-24T10:00:00Z','2026-11-24T11:00:00Z',1,'Dentist'),(2,'2026-11-25T13:00:00Z','2026-11-25T14:30:00Z',1,'secret'),(3,'2026-11-26T09:00:00Z','2026-11-26T10:00:00Z',0,'x')",
    "CREATE VIEW v_events AS SELECT id, start_at, end_at, busy FROM events",
    "CREATE TABLE accounts (region TEXT, arr REAL)", "INSERT INTO accounts VALUES ('EMEA',10),('EMEA',20),('AMER',5)", "CREATE VIEW v_accounts AS SELECT region, arr FROM accounts",
    "CREATE TABLE salaries (x INTEGER)", "CREATE VIEW v_salaries AS SELECT x FROM salaries",
  ]) await db.prepare(s).run();
});
after(() => mf?.dispose());

const holder = () => new Remit({ identity: sender, typecheck: false }).holder(url);
const READS = (h: any) => ({ busy: h.sql`SELECT start_at, end_at FROM calendar.events WHERE start_at < ${t.param("until", "timestamp")} AND busy`.maxRows(50) });
const kernel = async (source: string, returns: any, params: any = { until: "2026-12-01T00:00:00Z" }) => {
  const h = await holder();
  return h.kernel<any>({ reads: READS(h), params, returns, source, purpose: "scheduling", limits: { wall: "1s" } });
};

test("signed catalog, scoped to what the caller may see", async () => {
  const h = await holder();
  assert.deepEqual(h.catalog.resources.map((r: any) => r.name), ["calendar.events", "crm.accounts"]);
  assert.ok(!JSON.stringify(h.catalog).includes("title"));
});

test("query mode, typed and receipted", async () => {
  const h = await holder();
  const r = await h.query<any>({ sql: "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region ORDER BY region", returns: t.list(t.struct({ region: t.enum("AMER", "EMEA"), arr: t.float({ min: 0, max: 1e6, precision: 1 }) }), { max: 5 }), purpose: "scheduling" });
  assert.deepEqual(r.value, [{ region: "AMER", arr: 5 }, { region: "EMEA", arr: 30 }]);
  assert.equal((r.receipt as any).runtime.isolation, "cloudflare-dynamic-worker");
  const free = await h.query<boolean>({ sql: "SELECT COUNT(*) = 0 AS free FROM calendar.events WHERE start_at < $until AND end_at > $from AND busy", params: { from: "2026-11-24T10:30:00Z", until: "2026-11-24T10:45:00Z" }, returns: t.bool(), purpose: "scheduling" });
  assert.equal(free.value, false);
});

test("kernel mode in a dynamic worker", async () => {
  const r = await kernel("export default function main({ busy }, p) { return busy(p).rows().map(r => ({ start: r.start_at, h: (r.end_at - r.start_at) / 36e5 })); }", t.list(t.struct({ start: t.timestamp({ min: "2026-11-01T00:00:00Z", max: "2026-12-01T00:00:00Z", granularity: "1h" }), h: t.float({ min: 0, max: 24, precision: 0.5 }) }), { max: 4 }));
  assert.deepEqual(r.value.map((x: any) => [x.start.toISOString(), x.h]), [["2026-11-24T10:00:00.000Z", 1], ["2026-11-25T13:00:00.000Z", 1.5]]);
  assert.deepEqual(r.labels, ["no-forward", "personal"]);
  assert.deepEqual(r.terms, { retain_days: 30, forward: false });
});

test("no network, no ambient authority, frozen clock", async () => {
  const probe = await kernel("export default async function main() { let net = false; try { net = !!(await globalThis.fetch('https://example.com')); } catch {} return [net, typeof fetch !== 'undefined', typeof setTimeout !== 'undefined', typeof crypto !== 'undefined', Date.now() === Date.now() && new Date().getTime() === Date.now()]; }", t.list(t.bool(), { max: 5 }));
  assert.deepEqual(probe.value, [false, false, false, false, true]);
});

test("contained: wrong types, errors, loops, hidden data", async () => {
  const status = async (p: Promise<any>) => p.then(() => "ok", (e: any) => (e instanceof RemitError ? e.response?.status ?? e.diagnostics[0]?.code ?? e.decision : String(e)));
  assert.equal(await status(kernel("export default () => 'x'.repeat(99)", t.int({ min: 0, max: 1 }))), "type_violation");
  assert.equal(await status(kernel("export default () => { throw new Error('secret'); }", t.bool())), "internal");
  // CPU limits (`limits.cpuMs`) are enforced by Cloudflare's runtime, not by
  // local workerd, so the infinite-loop case is only meaningful when deployed.
  assert.equal(await status(kernel("import x from 'y'; export default () => 1", t.bool())), "denied");
  const h = await holder();
  const q = (sql: string, o: any = {}) => status(h.post("run", signManifest(bind({ holder: h.id, purpose: "scheduling", mode: "query", reads: { q: { sql, max_rows: 5, max_calls: 1 } }, params: {}, limits: {}, returns: { list: { max: 5, of: { struct: { x: { string: { max_len: 8 } } } } } }, ...o } as any, sender), sender)).then((r: any) => { if (r.decision === "rejected") throw new RemitError("rejected", r.diagnostics, null); return r; }));
  assert.equal(await q("SELECT title AS x FROM calendar.events"), "RMT-E0213");
  assert.equal(await q("SELECT title AS x FROM events"), "RMT-E0212");
  assert.equal(await q("SELECT x FROM hr.salaries"), "RMT-E0212");
  assert.equal(await q("SELECT name AS x FROM sqlite_master"), "RMT-E0212");
  assert.equal(await q("SELECT region AS x FROM crm.accounts"), "RMT-E0304");
  assert.equal(await q("SELECT x FROM crm.accounts; DROP TABLE events"), "RMT-E0202");
  assert.equal(await q("SELECT COUNT(*) AS n FROM calendar.events", { purpose: "marketing", returns: { int: { min: 0, max: 9 } } }), "RMT-E0050");
});

test("settles failures, versions snapshots, and measures UTF-8 bytes", async () => {
  const h = await holder();
  const db = await mf.getD1Database("DB");
  const spent = async () => (await db.prepare("SELECT bits FROM remit_bits WHERE scope = ?").bind(`p:${sender.id}`).first("bits")) as number;
  const before = await spent();
  const m = bind({ holder: h.id, purpose: "scheduling", mode: "query", reads: { q: { sql: "SELECT COUNT(*) AS n FROM calendar.events", max_rows: 1 } }, params: {}, limits: {}, returns: { string: { max_len: 4, charset: "ascii" } } } as any, sender);
  const failed = await h.post("run", signManifest(m, sender));
  assert.equal(failed.status, "type_violation");
  assert.equal(h.verifyReceipt(failed.receipt).charged.bits, 3);
  assert.equal((await spent()) - before, 3);
  assert.ok(h.verifyReceipt(failed.receipt).data_versions["calendar.events"]);
  const query = () => h.query({ sql: "SELECT COUNT(*) AS n FROM calendar.events", returns: t.int({ min: 0, max: 100 }), purpose: "scheduling" });
  const a = await query();
  await db.prepare("UPDATE events SET busy = 0 WHERE id = 1").run();
  const b = await query();
  assert.notEqual(a.receipt.data_versions["calendar.events"], b.receipt.data_versions["calendar.events"]);
  await db.prepare("UPDATE events SET busy = 1 WHERE id = 1").run();
  await assert.rejects(h.kernel({ reads: { q: { sql: "SELECT id FROM calendar.events", max_rows: 3 } }, source: 'export default () => "😀";', returns: t.string({ max_len: 1 }), purpose: "scheduling", limits: { output_bytes: 4 } }), (e: any) => e.decision === "limit_exceeded");
});

test("replay, wrong signer, expiry, budgets", async () => {
  const h = await holder();
  const m = bind({ holder: h.id, purpose: "scheduling", mode: "query", reads: { q: { sql: "SELECT COUNT(*) AS n FROM calendar.events", max_rows: 5, max_calls: 1 } }, params: {}, limits: {}, returns: { int: { min: 0, max: 9 } } } as any, sender);
  const env = signManifest(m, sender);
  assert.equal((await h.post("run", env)).result, 3);
  assert.equal((await h.post("run", env)).diagnostics[0].code, "RMT-E0024");
  assert.equal((await h.post("run", signManifest({ ...m, nonce: "another-nonce" }, Identity.generate(sender.id)))).diagnostics[0].code, "RMT-E0010");
  assert.equal((await h.post("run", signManifest({ ...m, nonce: "another-nonce", expires_at: "2020-01-01T00:00:00Z" }, sender))).diagnostics[0].code, "RMT-E0021");
  // Same params, concurrently: the bit budget is never exceeded.
  const big = () => signManifest({ ...m, nonce: crypto.randomUUID(), returns: { list: { max: 20, of: { struct: { n: { int: { min: 0, max: 15 } } } } } } } as any, sender);
  const rs = await Promise.all(Array.from({ length: 40 }, () => h.post("run", big())));
  const spent = rs.filter((r) => r.receipt).length;
  assert.ok(spent < 40 && rs.some((r) => r.diagnostics?.[0].code === "RMT-E0060"), `${spent}`);
  void codeBlock;
});
