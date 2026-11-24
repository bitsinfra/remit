import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { BrowserHolder, BrowserRemit, WebIdentity } from "../src/browser.ts";
import { canonicalize, Identity, paramsSha256, RECEIPT_TYPE, remitId, sha256Hex, signEnvelope } from "../src/index.ts";

const verifier = createRequire(import.meta.url)("../wasm/remit_verify_wasm.js");

test("browser binds parameters and verifies results and restrictions", async (context) => {
  const key = Identity.generate("did:web:holder.example");
  const remit = new BrowserRemit(await WebIdentity.generate(), verifier);
  const holder = new BrowserHolder(remit, "https://holder.example", { holder: key.id, keys: [{ did_key: key.didKey }] });
  const p = { sql: "SELECT COUNT(*) AS n FROM calendar.events WHERE start_at < $until AND busy = $busy", params: { until: new Date("2026-12-01T00:00:00Z"), busy: true }, returns: { int: { min: 0, max: 10 } }, purpose: "scheduling" };
  let change: (receipt: any) => void = () => {};
  let value = 4;
  context.mock.method(globalThis, "fetch", async (_url: string, init: RequestInit) => {
    const m = JSON.parse(Buffer.from(JSON.parse(init.body as string).payload, "base64").toString());
    assert.deepEqual(m.reads.q.params, { until: "timestamp", busy: "bool" });
    assert.equal(m.params.until, "2026-12-01T00:00:00.000Z");
    const receipt = { decision: "admitted", status: "ok", remit_id: remitId(m), params_sha256: paramsSha256(m), sender: m.sender, holder: m.holder, result_sha256: `sha256:${sha256Hex(canonicalize(value))}`, labels: ["no-forward"], terms: { forward: false, retain_days: 7 } };
    change(receipt);
    return new Response(JSON.stringify({ status: "ok", result: value, labels: [], terms: { forward: true }, receipt: signEnvelope(RECEIPT_TYPE, Buffer.from(canonicalize(receipt)), key) }));
  });
  const result = await holder.run(p);
  assert.equal(result.value, 4);
  assert.deepEqual(result.response.labels, ["no-forward"]);
  assert.deepEqual(result.response.terms, { forward: false, retain_days: 7 });
  for (const field of ["remit_id", "params_sha256", "sender", "holder", "status", "decision"]) {
    change = (receipt) => { receipt[field] = "other"; };
    await assert.rejects(holder.run(p), /does not match the submitted remit/);
  }
  change = () => {};
  value = 99;
  await assert.rejects(holder.run(p), /does not inhabit/);
  value = 0.15;
  await assert.rejects(holder.run({ ...p, returns: { float: { min: 0, max: 1, precision: 0.1 } } }), /does not inhabit/);
  const unchecked = new BrowserHolder(new BrowserRemit(remit.identity), holder.url, holder.catalog);
  await assert.rejects(unchecked.run(p), /BrowserVerifier is required/);
});
