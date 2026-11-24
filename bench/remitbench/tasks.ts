// RemitBench core task set. Ground truth is computed from the CSVs by `truth`.
export interface Task {
  id: string;
  domain: "personal" | "enterprise" | "documents" | "b2b";
  holder: "vault" | "crm" | "docs" | "b2b";
  question: string;
  /** Reference Remit program. */
  remit: any;
  /** Baseline: tool calls the MCP-tools agent makes, then how it computes the answer. */
  baseline: { calls: { tool: string; args: any }[]; answer: (results: any[][], d: Data) => unknown };
  truth: (d: Data) => unknown;
  /** Compare remit/baseline answers with truth. */
  check: (got: unknown, want: unknown) => boolean;
}

export interface Data {
  events: any[];
  accounts: any[];
  deals: any[];
  customers: any[];
  companyA: string[];
  chunks: any[];
}

const FROM = "2026-11-24T00:00:00Z", UNTIL = "2026-12-08T00:00:00Z";
const confirmed = (e: any) => e.status !== "cancelled";
const overlaps = (e: any, a: string, b: string) => e.start_at < b && e.end_at > a;

function freeSlots(events: any[], from: string, until: string, minutes: number) {
  const H = 3_600_000, need = minutes * 60_000, step = 15 * 60_000;
  const taken = events.filter(confirmed).filter((e) => overlaps(e, from, until)).map((e) => [Date.parse(e.start_at), Date.parse(e.end_at)]).sort((a, b) => a[0] - b[0]);
  const out: string[][] = [];
  for (let day = Date.parse(from); day < Date.parse(until) && out.length < 3; day += 24 * H) {
    let t = day + 9 * H;
    const close = day + 18 * H;
    for (const [s, e] of taken) {
      if (e <= t || s >= close) continue;
      if (s - t >= need && out.length < 3) out.push([new Date(t).toISOString(), new Date(t + need).toISOString()]);
      t = Math.max(t, Math.ceil(e / step) * step);
    }
    if (out.length < 3 && close - t >= need) out.push([new Date(t).toISOString(), new Date(t + need).toISOString()]);
  }
  return out;
}

const KERNEL_FREE = `export default function main({ busy }, p) {
  const H = 3600000, need = p.minutes * 60000, step = 900000;
  const taken = busy(p).rows().map(r => [+r.start_at, +r.end_at]).sort((a, b) => a[0] - b[0]);
  const out = [];
  for (let day = +p.from; day < +p.until && out.length < 3; day += 24 * H) {
    let t = day + 9 * H; const close = day + 18 * H;
    for (const [s, e] of taken) {
      if (e <= t || s >= close) continue;
      if (s - t >= need && out.length < 3) out.push({ start: new Date(t), end: new Date(t + need) });
      t = Math.max(t, Math.ceil(e / step) * step);
    }
    if (out.length < 3 && close - t >= need) out.push({ start: new Date(t), end: new Date(t + need) });
  }
  return out;
}`;

const ts = (min: string, max: string, g: string) => ({ timestamp: { min, max, granularity: g } });
const sameJSON = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const approx = (tol: number) => (a: any, b: any) => {
  const ka = Object.keys(a ?? {}).sort(), kb = Object.keys(b ?? {}).sort();
  return sameJSON(ka, kb) && ka.every((k) => Math.abs(Number(a[k]) - Number(b[k])) <= tol * Math.max(1, Math.abs(Number(b[k]))));
};
const sumBy = (rows: any[], key: string, val: (r: any) => number) => {
  const m: Record<string, number> = {};
  for (const r of rows) m[r[key]] = (m[r[key]] ?? 0) + val(r);
  return m;
};

export const TASKS: Task[] = [
  {
    id: "vault-free-slots",
    domain: "personal",
    holder: "vault",
    question: "Find three free 2-hour slots between 09:00 and 18:00 UTC from 2026-11-24 to 2026-12-08.",
    remit: {
      mode: "kernel",
      reads: { busy: { sql: "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'", params: { from: "timestamp", until: "timestamp" }, max_rows: 500 } },
      source: KERNEL_FREE,
      params: { from: FROM, until: UNTIL, minutes: 120 },
      returns: { list: { max: 3, of: { struct: { start: ts("$from", "$until", "15m"), end: ts("$from", "$until", "15m") } } } },
      purpose: "scheduling",
    },
    baseline: { calls: [{ tool: "list_events", args: { from: FROM, until: UNTIL } }], answer: ([ev]) => freeSlots(ev, FROM, UNTIL, 120) },
    truth: (d) => freeSlots(d.events, FROM, UNTIL, 120),
    check: (got: any, want) => sameJSON(Array.isArray(got) && got[0]?.start ? got.map((s: any) => [new Date(s.start).toISOString(), new Date(s.end).toISOString()]) : got, want),
  },
  {
    id: "vault-busy-count",
    domain: "personal",
    holder: "vault",
    question: "How many confirmed events overlap 2026-11-25?",
    remit: {
      mode: "query",
      sql: "SELECT COUNT(*) AS n FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'",
      params: { from: "2026-11-25T00:00:00Z", until: "2026-11-26T00:00:00Z" },
      returns: { int: { min: 0, max: 64 } },
      purpose: "scheduling",
    },
    baseline: { calls: [{ tool: "list_events", args: { from: "2026-11-25T00:00:00Z", until: "2026-11-26T00:00:00Z" } }], answer: ([ev]) => ev.filter(confirmed).length },
    truth: (d) => d.events.filter(confirmed).filter((e) => overlaps(e, "2026-11-25T00:00:00Z", "2026-11-26T00:00:00Z")).length,
    check: sameJSON,
  },
  {
    id: "vault-is-free",
    domain: "personal",
    holder: "vault",
    question: "Is Alice free on 2026-11-26 from 15:00 to 16:00 UTC?",
    remit: {
      mode: "query",
      sql: "SELECT COUNT(*) = 0 AS free FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'",
      params: { from: "2026-11-26T15:00:00Z", until: "2026-11-26T16:00:00Z" },
      returns: "bool",
      purpose: "scheduling",
    },
    baseline: { calls: [{ tool: "list_events", args: { from: "2026-11-26T15:00:00Z", until: "2026-11-26T16:00:00Z" } }], answer: ([ev]) => ev.filter(confirmed).length === 0 },
    truth: (d) => d.events.filter(confirmed).filter((e) => overlaps(e, "2026-11-26T15:00:00Z", "2026-11-26T16:00:00Z")).length === 0,
    check: sameJSON,
  },
  {
    id: "crm-arr-by-region",
    domain: "enterprise",
    holder: "crm",
    question: "Total ARR per region (rounded to $1k).",
    remit: {
      mode: "query",
      sql: "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region",
      params: {},
      returns: { list: { max: 10, of: { struct: { region: { enum: ["AMER", "APAC", "EMEA", "LATAM"] }, arr: { float: { min: 0, max: 1e10, precision: 1000 } } } } } },
      purpose: "analytics",
      post: (v: any[]) => Object.fromEntries(v.map((r) => [r.region, r.arr])),
    },
    baseline: { calls: [{ tool: "list_accounts", args: {} }], answer: ([a]) => sumBy(a, "region", (r) => Number(r.arr)) },
    truth: (d) => sumBy(d.accounts, "region", (r) => Number(r.arr)),
    check: approx(0.001),
  },
  {
    id: "crm-emea-segments",
    domain: "enterprise",
    holder: "crm",
    question: "How many EMEA accounts are in each segment?",
    remit: {
      mode: "query",
      sql: "SELECT segment, COUNT(*) AS n FROM crm.accounts WHERE region = 'EMEA' GROUP BY segment",
      params: {},
      returns: { list: { max: 3, of: { struct: { segment: { enum: ["smb", "mid", "enterprise"] }, n: { int: { min: 0, max: 100000 } } } } } },
      purpose: "analytics",
      post: (v: any[]) => Object.fromEntries(v.map((r) => [r.segment, r.n])),
    },
    baseline: { calls: [{ tool: "list_accounts", args: { region: "EMEA" } }], answer: ([a]) => sumBy(a, "segment", () => 1) },
    truth: (d) => sumBy(d.accounts.filter((a) => a.region === "EMEA"), "segment", () => 1),
    check: approx(0),
  },
  {
    id: "crm-won-since",
    domain: "enterprise",
    holder: "crm",
    question: "Number of won deals and their total amount since 2026-01-01.",
    remit: {
      mode: "query",
      sql: "SELECT COUNT(*) AS n, SUM(amount) AS total, COUNT(DISTINCT account_id) AS accts FROM crm.deals WHERE stage = 'won' AND closed_at >= $since",
      params: { since: "2026-01-01T00:00:00Z" },
      returns: { struct: { n: { int: { min: 0, max: 1000000 } }, total: { float: { min: 0, max: 1e12, precision: 1 } }, accts: { int: { min: 0, max: 1000000 } } } },
      purpose: "analytics",
      post: (v: any) => ({ n: v.n, total: v.total }),
    },
    baseline: {
      calls: [{ tool: "list_deals", args: { stage: "won" } }],
      answer: ([d]) => {
        const w = d.filter((x: any) => x.closed_at >= "2026-01-01T00:00:00Z");
        return { n: w.length, total: w.reduce((s: number, x: any) => s + Number(x.amount), 0) };
      },
    },
    truth: (d) => {
      const w = d.deals.filter((x) => x.stage === "won" && x.closed_at >= "2026-01-01T00:00:00Z");
      return { n: w.length, total: w.reduce((s, x) => s + Number(x.amount), 0) };
    },
    check: approx(0.0001),
  },
  {
    id: "crm-win-rate",
    domain: "enterprise",
    holder: "crm",
    question: "Win rate (won / closed) per segment since 2025-06-01.",
    remit: {
      mode: "kernel",
      reads: {
        won: { sql: "SELECT a.segment AS segment, COUNT(*) AS n, COUNT(DISTINCT d.account_id) AS accts FROM crm.deals d JOIN crm.accounts a ON a.account_id = d.account_id WHERE d.stage = 'won' AND d.closed_at >= $since GROUP BY a.segment", params: { since: "timestamp" }, max_rows: 10 },
        all: { sql: "SELECT a.segment AS segment, COUNT(*) AS n, COUNT(DISTINCT d.account_id) AS accts FROM crm.deals d JOIN crm.accounts a ON a.account_id = d.account_id WHERE d.stage <> 'open' AND d.closed_at >= $since GROUP BY a.segment", params: { since: "timestamp" }, max_rows: 10 },
      },
      source: "export default function main({ won, all }, p) { const w = new Map(won(p).rows().map(r => [r.segment, r.n])); return all(p).rows().map(r => ({ segment: r.segment, win_rate: (w.get(r.segment) ?? 0) / r.n })); }",
      params: { since: "2025-06-01T00:00:00Z" },
      returns: { list: { max: 3, of: { struct: { segment: { enum: ["smb", "mid", "enterprise"] }, win_rate: { float: { min: 0, max: 1, precision: 0.01 } } } } } },
      purpose: "forecasting",
      post: (v: any[]) => Object.fromEntries(v.map((r) => [r.segment, r.win_rate])),
    },
    baseline: {
      calls: [{ tool: "list_deals", args: {} }, { tool: "list_accounts", args: {} }],
      answer: ([d, a]) => winRate(d, a),
    },
    truth: (d) => winRate(d.deals, d.accounts),
    check: (got: any, want: any) => Object.keys(want).every((k) => Math.abs(got[k] - want[k]) <= 0.0051),
  },
  {
    id: "b2b-overlap",
    domain: "b2b",
    holder: "b2b",
    question: "How many of Company A's 400 customers are also Company B's customers?",
    remit: {
      mode: "kernel",
      reads: { customers: { sql: "SELECT email_sha256 FROM crm.customers", max_rows: 10000 } },
      source: "export default function main({ customers }, p) { const s = new Set(customers({}).col('email_sha256')); let n = 0; for (const h of p.mine) if (s.has(h)) n++; return n < 10 ? 0 : n; }",
      params: { mine: "$companyA" },
      returns: { int: { min: 0, max: 10000 } },
      limits: { fuel: 400000000, wall_ms: 3000, memory_bytes: 67108864 },
      purpose: "overlap",
    },
    baseline: { calls: [{ tool: "list_customers", args: {} }], answer: ([c], d) => { const s = new Set(c.map((x: any) => x.email)); return d.companyA.filter((e) => s.has(e)).length; } },
    truth: (d) => {
      const s = new Set(d.customers.map((c) => c.email));
      return d.companyA.filter((e) => s.has(e)).length;
    },
    check: sameJSON,
  },
];

function winRate(deals: any[], accounts: any[]) {
  const seg = new Map(accounts.map((a) => [a.account_id, a.segment]));
  const closed = deals.filter((d) => d.stage !== "open" && d.closed_at >= "2025-06-01T00:00:00Z");
  const won = sumBy(closed.filter((d) => d.stage === "won"), "segment_", () => 1);
  const out: Record<string, number> = {};
  const all: Record<string, number> = {};
  const wonBy: Record<string, number> = {};
  for (const d of closed) {
    const s = seg.get(d.account_id)!;
    all[s] = (all[s] ?? 0) + 1;
    if (d.stage === "won") wonBy[s] = (wonBy[s] ?? 0) + 1;
  }
  void won;
  for (const s of Object.keys(all)) out[s] = Math.round(((wonBy[s] ?? 0) / all[s]) * 100) / 100;
  return out;
}
