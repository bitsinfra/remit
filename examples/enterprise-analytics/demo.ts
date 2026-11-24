// Sender side: a finance agent asks the CRM Holder aggregate-only questions.
import { readFileSync } from "node:fs";
import { z } from "zod";
import { Remit, RemitError, t } from "../../sdk/ts/src/index.ts";

const remit = new Remit({ identity: await Remit.identity.fromEnv() });
const crm = await remit.holder(process.env.HOLDER ?? "http://127.0.0.1:8444");

// Query mode with a Zod return type.
const arr = await crm.query({
  sql: "SELECT region, SUM(arr) AS arr, COUNT(*) AS accounts FROM crm.accounts GROUP BY region ORDER BY region",
  returns: z.array(z.object({ region: z.enum(crm.enums("crm.accounts.region") as [string, ...string[]]), arr: z.number().min(0).max(1e10).multipleOf(1000), accounts: z.number().int().min(0).max(100000) })).max(10),
  purpose: "analytics",
});
console.log("ARR by region (k ≥ 20 enforced in the plan):", arr.value);

// Kernel over aggregates: win rate per segment.
const w = JSON.parse(readFileSync(new URL("./remits/win-rate-kernel.json", import.meta.url), "utf8"));
const wr = await crm.kernel({ reads: w.reads, params: { since: new Date("2025-06-01T00:00:00Z") }, returns: w.returns, source: w.code.source, limits: { fuel: 20_000_000, wall: "500ms" }, purpose: "forecasting" });
console.log("win rate by segment:", wr.value);

// Differential privacy: noisy COUNT/SUM with ε = 0.3; an identical request returns the cached answer at no extra ε.
const dpq = { sql: "SELECT segment, COUNT(*) AS accounts, SUM(arr) AS arr FROM finance.arr_dp GROUP BY segment", returns: t.list(t.struct({ segment: t.enum("smb", "mid", "enterprise"), accounts: t.int({ min: 0, max: 100000 }), arr: t.float({ min: -1e10, max: 1e10, precision: 1000 }) }), { max: 10 }), limits: { epsilon: 0.3 }, purpose: "analytics" };
const dp1 = await crm.query(dpq);
const dp2 = await crm.query(dpq);
console.log("DP answer:", dp1.value, "charged ε", dp1.receipt.charged.epsilon, "| repeat cached:", dp2.cached, "charged ε", dp2.receipt.charged.epsilon);

// Raw rows are refused: the resource is aggregate-only.
try {
  await crm.query({ sql: "SELECT account_id, arr FROM crm.accounts", returns: t.list(t.struct({ account_id: t.string({ max_len: 16 }), arr: t.float({ min: 0, max: 1e10, precision: 1 }) }), { max: 100 }), purpose: "analytics" });
} catch (e) {
  if (e instanceof RemitError) console.log("rejected:", e.diagnostics.map((d) => `${d.code} ${d.message}`));
  else throw e;
}
