import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalize, contentDigest, estimateFuel, Identity, kernelDts, localVerifier, pae, publicKeyFromDidKey, Remit, RemitError, sha256Hex, signEnvelope, signRequest, sqlGrammar, t, toRT, typecheckKernel,
  verifySignature, RECEIPT_TYPE, CATALOG_TYPE, remitId, paramsSha256, typesDts,
} from "../src/index.ts";

const CATALOG = {
  remit: "0.1", holder: "did:web:h.example", purposes: ["scheduling"], catalog_sha256: "sha256:x",
  resources: [{ name: "calendar.events", rows: "≤1K", columns: [{ name: "start_at", type: "timestamp", nullable: false }, { name: "end_at", type: "timestamp", nullable: false }, { name: "status", type: "string", enum: ["confirmed", "cancelled"] }], hints: { max_bits_per_remit: 128 } }],
  runtime: { fuel_prices: { per_call: 50_000, per_row: 200, per_byte: 1 }, functions: [{ name: "embed", description: "embed text", fuel: 9 }] },
};

test("P-256 identities interoperate with the shared file format", () => {
  const id = Identity.generateP256("did:web:hsm.example");
  assert.match(id.didKey, /^did:key:zDn/);
  const msg = Buffer.from("hello");
  const pk = publicKeyFromDidKey(id.didKey)!;
  assert.equal(pk.length, 33);
  assert.ok(verifySignature(pk, msg, id.sign(msg)));
  assert.ok(!verifySignature(pk, Buffer.from("hellO"), id.sign(msg)));
  const again = Identity.fromJSON(JSON.parse(JSON.stringify(id)));
  assert.equal(again.didKey, id.didKey);
  assert.ok(verifySignature(pk, msg, again.sign(msg)));
});

test("RFC 9421 request signatures", () => {
  for (const id of [Identity.generate(), Identity.generateP256()]) {
    const h = signRequest(id, "POST", "https://Alice.example/remit/v1/run?x=1", "{}", { now: 1000 });
    assert.equal(h["content-digest"], contentDigest("{}"));
    const params = h["signature-input"].replace(/^sig1=/, "");
    const base = `"@method": POST\n"@authority": alice.example\n"@path": /remit/v1/run\n"content-digest": ${h["content-digest"]}\n"@query": ?x=1\n"@signature-params": ${params}`;
    const sig = Buffer.from(/^sig1=:(.*):$/.exec(h.signature)![1], "base64");
    assert.ok(verifySignature(publicKeyFromDidKey(id.didKey)!, Buffer.from(base), sig));
  }
});

const READS = { busy: { sql: "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from", params: { from: "timestamp", until: "timestamp" } as const, max_rows: 500 } };
const RETURNS = t.list(t.struct({ start: t.timestamp({ granularity: "15m" }), end: t.timestamp({ granularity: "15m" }) }), { max: 3 });

test("kernels are type-checked against reads, params and result", () => {
  const dts = kernelDts({ reads: READS as any, params: { from: new Date(), until: new Date(), minutes: 120 }, returns: toRT(RETURNS), catalog: CATALOG, verifier: localVerifier() });
  const ok = typecheckKernel(`export default function main({ busy }: Reads, p: Params): Result {
    const taken = busy(p).rows().map(r => [+r.start_at, +r.end_at]);
    return taken.slice(0, 3).map(([s]) => ({ start: new Date(s), end: new Date(s + p.minutes * 60000) }));
  }`, dts);
  assert.deepEqual(ok, [], JSON.stringify(ok));
  {
    const bad = typecheckKernel("export default function main({ busy }: Reads, p: Params): Result {\n  return busy(p).rows().map(r => ({ start: r.titel, end: r.end_at }));\n}", dts)!;
    assert.ok(bad.some((d) => d.code === "RMT-E0610" && /titel/.test(d.message) && d.span?.[0] === 2), JSON.stringify(bad));
  }
  assert.deepEqual(typecheckKernel("interface Reads { busy(p: Params): { rows(): { start_at: Date }[] } }\ninterface Params { minutes: number }\nexport default function main({ busy }: Reads, p: Params): Result { return []; }", dts), [], "a kernel may declare its own types");
  assert.ok(typecheckKernel("export default function main(): string { return 'x'; }", dts)!.length > 0, "wrong result type");
  assert.ok(typecheckKernel("export default function main({ other }: Reads) { return []; }", dts)!.length > 0, "undeclared read");
  assert.ok(typecheckKernel("export default async function main() { return fetch('x') as any; }", dts)!.length > 0, "no ambient fetch");
});

test("fuel estimates are bounded by the catalog's row buckets", () => {
  const a = estimateFuel({ mode: "kernel", reads: { r: { sql: "SELECT * FROM calendar.events", max_rows: 1_000_000 } } } as any, CATALOG);
  const b = estimateFuel({ mode: "kernel", reads: { r: { sql: "SELECT * FROM calendar.events", max_rows: 1000 } } } as any, CATALOG);
  assert.equal(a.total, b.total);
  assert.ok(a.host_max > 200_000 && a.total > a.host_max);
});

test("grammar and types come from the catalog only", () => {
  const g = sqlGrammar(CATALOG);
  assert.ok(g.includes('table ::= "calendar.events"') && g.includes('"start_at"') && !/random|now\(/.test(g));
  assert.ok(typesDts(CATALOG).includes('holder.call("embed", args)'));
});

/** A Holder double whose behaviour each test controls. */
function fakeHolder(o: { tamper?: (resp: any) => void; value?: unknown; busy?: number } = {}) {
  const key = Identity.generate("did:web:h.example");
  const cat = { ...CATALOG, keys: [{ kid: key.keyId, did_key: key.didKey }] };
  const log: { url: string; headers: any; body: any }[] = [];
  let busy = o.busy ?? 0;
  const f = async (url: any, init: any = {}) => {
    const u = String(url);
    log.push({ url: u, headers: init.headers ?? {}, body: init.body });
    if (u.endsWith("/.well-known/remit")) {
      const sig = Buffer.from(key.sign(pae(CATALOG_TYPE, Buffer.from(canonicalize(cat))))).toString("base64");
      return new Response(JSON.stringify(cat), { headers: { "remit-signature": `keyid="${key.keyId}", sig="${sig}"` } });
    }
    if (u.includes("/blobs/")) return new Response("{}", { status: 201 });
    if (busy-- > 0) return new Response(JSON.stringify({ decision: "busy" }), { status: 429, headers: { "retry-after": "0" } });
    const m = JSON.parse(Buffer.from(JSON.parse(init.body).payload, "base64").toString());
    const result = o.value ?? 4;
    const receipt = { run_id: "r", remit_id: remitId(m), params_sha256: paramsSha256(m), sender: m.sender, holder: cat.holder, decision: "admitted", status: "ok", result_sha256: `sha256:${sha256Hex(canonicalize(result))}`, result_bits_max: 5, labels: [], terms: { forward: true }, charged: { bits: 5, epsilon: 0 }, data_versions: {} };
    const resp: any = { run_id: "r", status: "ok", result, labels: [], terms: {}, provenance: {}, receipt: signEnvelope(RECEIPT_TYPE, Buffer.from(canonicalize(receipt)), key), usage: {}, cached: false };
    o.tamper?.(resp);
    return new Response(JSON.stringify(resp));
  };
  return { f: f as unknown as typeof fetch, log };
}

const Q = { sql: "SELECT COUNT(*) AS n FROM calendar.events", returns: t.int({ min: 0, max: 10 }) };

test("results must match the signed receipt and inhabit the declared type", async () => {
  const run = async (o: any) => {
    const h = fakeHolder(o);
    return (await new Remit({ identity: Identity.generate(), fetch: h.f }).holder("http://h")).query(Q);
  };
  assert.equal((await run({})).value, 4);
  await assert.rejects(run({ tamper: (r: any) => (r.result = 5) }), /does not match the signed receipt/);
  await assert.rejects(run({ tamper: (r: any) => (r.receipt.signatures[0].sig = Buffer.alloc(64).toString("base64")) }), /does not verify/);
  await assert.rejects(run({ value: 99 }), /does not inhabit/);
  const fractional = fakeHolder({ value: 0.15 });
  const h = await new Remit({ identity: Identity.generate(), fetch: fractional.f }).holder("http://h");
  await assert.rejects(h.query({ ...Q, returns: t.float({ min: 0, max: 1, precision: 0.1 }) }), /does not inhabit/);
});

test("local binding catches bad columns before anything is sent", async () => {
  const h = fakeHolder();
  const holder = await new Remit({ identity: Identity.generate(), fetch: h.f }).holder("http://h");
  await assert.rejects(holder.query({ ...Q, sql: "SELECT COUNT(titel) AS n FROM calendar.events" }), (e: any) => e instanceof RemitError && e.diagnostics[0].code === "RMT-E0213");
  assert.equal(h.log.filter((l) => l.url.endsWith("/run")).length, 0);
});

test("busy retries, signed requests, blob upload, scoped catalogs", async () => {
  const h = fakeHolder({ busy: 2 });
  const holder = await new Remit({ identity: Identity.generate(), fetch: h.f, inlineCodeBytes: 10, headers: () => ({ "workload-identity-token": "wit" }) }).holder("http://h", { scoped: true });
  assert.ok(h.log[1].headers["remit-proof"]);
  const r = await holder.kernel({ reads: { busy: holder.sql`SELECT start_at FROM calendar.events`.maxRows(5) }, returns: t.int({ min: 0, max: 10 }), source: "export default function main({ busy }) { return busy({}).length; }" });
  assert.equal(r.value, 4);
  const runs = h.log.filter((l) => l.url.endsWith("/run"));
  assert.equal(runs.length, 3);
  const nonces = new Set(runs.map((l) => JSON.parse(Buffer.from(JSON.parse(l.body).payload, "base64").toString()).nonce));
  assert.equal(nonces.size, 3, "every retry is a fresh envelope");
  assert.ok(runs[0].headers.signature && runs[0].headers["workload-identity-token"] === "wit");
  assert.ok(h.log.some((l) => l.url.includes("/blobs/")));
  const m = JSON.parse(Buffer.from(JSON.parse(runs[0].body).payload, "base64").toString());
  assert.equal(m.code.source, undefined);
});


test("restrictions come from the signed receipt", async () => {
  const fake = fakeHolder({ tamper: (response: any) => {
    response.labels = ["unsigned"];
    response.terms = { forward: false, retain_days: 999 };
  } });
  const h = await new Remit({ identity: Identity.generate(), fetch: fake.f }).holder("http://h");
  const result = await h.query(Q);
  assert.deepEqual(result.labels, result.receipt.labels);
  assert.deepEqual(result.terms, result.receipt.terms);
});
