// Multi-Holder graph: count Alice's busy events, then ask the CRM Holder an
// aggregate question parameterized by that typed value. Run both example
// Holders first (personal-vault :8443, enterprise-analytics :8444).
import { Identity, Remit, runGraph, t } from "../sdk/ts/src/index.ts";

const vault = await new Remit({ identity: Identity.load(new URL("./personal-vault/keys/travel-agent.json", import.meta.url).pathname) }).holder("http://127.0.0.1:8443");
const crm = await new Remit({ identity: Identity.load(new URL("./enterprise-analytics/keys/finance-agent.json", import.meta.url).pathname) }).holder("http://127.0.0.1:8444");
const g = await runGraph<{ busy: number; accounts: { region: string; n: number }[] }>([
  { name: "busy", holder: vault, run: (h) => h.query({ sql: "SELECT COUNT(*) AS n FROM calendar.events WHERE start_at < $until AND end_at > $from", params: { from: "2026-11-24T00:00:00Z", until: "2026-12-08T00:00:00Z" }, returns: t.int({ min: 0, max: 1000 }), purpose: "scheduling" }) },
  {
    name: "accounts",
    holder: crm,
    run: (h, ctx) => h.query({ sql: "SELECT region, COUNT(*) AS n FROM crm.accounts WHERE arr >= $floor GROUP BY region ORDER BY region", params: { floor: ctx.busy * 1000.5 }, returns: t.list(t.struct({ region: t.enum(...h.enums("crm.accounts.region")), n: t.int({ min: 0, max: 100000 }) }), { max: 10 }), purpose: "analytics" }),
  },
]);
console.log(g.values, g.labels, g.terms);
console.log(g.provenance);
