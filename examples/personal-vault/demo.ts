// Sender side: a travel agent asks Alice's vault for three free 2-hour slots.
// Run the Holder first: `remit serve` (in this directory).
import { readFileSync } from "node:fs";
import { Remit, RemitError, t } from "../../sdk/ts/src/index.ts";

const remit = new Remit({ identity: await Remit.identity.fromEnv() });
const alice = await remit.holder(process.env.HOLDER ?? "http://127.0.0.1:8443");
console.log("catalog:", alice.catalog.policy_hints);

const params = { from: new Date("2026-11-24T00:00:00Z"), until: new Date("2026-12-08T00:00:00Z"), minutes: 120 };
const slots = await alice.kernel<{ start: Date; end: Date }[]>({
  reads: {
    busy: alice.sql`SELECT start_at, end_at FROM calendar.events
                    WHERE start_at < ${t.param("until")} AND end_at > ${t.param("from")} AND status <> 'cancelled'`.maxRows(500),
  },
  params,
  returns: t.list(t.struct({ start: t.timestamp({ granularity: "15m" }), end: t.timestamp({ granularity: "15m" }) }), { max: 3 }),
  limits: { wall: "250ms", memory: "16MiB", fuel: 50_000_000, output: "1KiB" },
  source: readFileSync(new URL("./kernels/free-slots.ts", import.meta.url), "utf8"),
  purpose: "scheduling",
});
console.log("free slots:", slots.value.map((s) => `${s.start.toISOString()} → ${s.end.toISOString()}`));
console.log("bits revealed ≤", slots.receipt.result_bits_max, "labels", slots.labels, "terms", slots.terms, "cached", slots.cached);

// A remit that tries to read titles is rejected mechanically, with a located diagnostic.
try {
  await alice.query({ sql: "SELECT title FROM calendar.events", returns: t.list(t.string({ max_len: 64 }), { max: 10 }), purpose: "scheduling" });
} catch (e) {
  if (e instanceof RemitError) console.log("rejected:", e.diagnostics.map((d) => `${d.code} ${d.message}`));
  else throw e;
}
