// RemitBench v1: 200 tasks (50 per domain) generated deterministically from
// parameterized families. Ground truth comes from the CSVs, independently of
// the reference programs; the same families define the MCP-tools baseline.
import { createHash } from "node:crypto";
import { type Data, type Task, TASKS as V0 } from "./tasks.ts";

const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z");
const DAY = 86_400_000, H = 3_600_000;
const D0 = Date.parse("2026-11-24T00:00:00Z");
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const num = (tol: number) => (a: any, b: any) => Math.abs(Number(a) - Number(b)) <= tol * Math.max(1, Math.abs(Number(b)));
const rec = (tol: number) => (a: any, b: any) => same(Object.keys(a ?? {}).sort(), Object.keys(b ?? {}).sort()) && Object.keys(b).every((k) => num(tol)(a[k], b[k]));
const live = (e: any) => e.status !== "cancelled";
const overl = (e: any, a: string, b: string) => e.start_at < b && e.end_at > a;
const INT = (max: number) => ({ int: { min: 0, max } });
const sha = (e: string) => createHash("sha256").update(e.trim().toLowerCase()).digest("hex");

const out: Task[] = [];
const ids = new Set<string>();
function add(t: Task) {
  if (ids.has(t.id)) throw new Error(`duplicate ${t.id}`);
  ids.add(t.id);
  out.push(t);
}

// ------------------------------------------------------------- personal data
const ev = (from: string, until: string) => ({ calls: [{ tool: "list_events", args: { from, until } }] });
const BUSY = { sql: "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'", params: { from: "timestamp", until: "timestamp" }, max_rows: 500 };
for (let i = 0; i < 14; i++) {
  const from = iso(D0 + (i % 10) * DAY + (9 + ((i * 3) % 9)) * H), until = iso(Date.parse(from) + (i % 2 ? H : H / 2));
  const free = (es: any[]) => es.filter(live).filter((e) => overl(e, from, until)).length === 0;
  add({ id: `vault-is-free-${i}`, domain: "personal", holder: "vault", question: `Is Alice free from ${from} until ${until}?`,
    remit: { mode: "query", sql: "SELECT COUNT(*) = 0 AS free FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'", params: { from, until }, returns: "bool", purpose: "scheduling" },
    baseline: { ...ev(from, until), answer: ([e]) => free(e) }, truth: (d) => free(d.events), check: same });
}
for (let i = 0; i < 12; i++) {
  const from = iso(D0 + i * DAY), until = iso(D0 + (i + 1 + (i % 3)) * DAY);
  const n = (es: any[]) => es.filter(live).filter((e) => overl(e, from, until)).length;
  add({ id: `vault-busy-count-${i}`, domain: "personal", holder: "vault", question: `How many non-cancelled events overlap ${from} to ${until}?`,
    remit: { mode: "query", sql: "SELECT COUNT(*) AS n FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'", params: { from, until }, returns: INT(255), purpose: "scheduling" },
    baseline: { ...ev(from, until), answer: ([e]) => n(e) }, truth: (d) => n(d.events), check: same });
}
function busyMinutes(es: any[], from: string, until: string) {
  const iv = es.filter(live).filter((e) => overl(e, from, until)).map((e) => [Math.max(Date.parse(e.start_at), Date.parse(from)), Math.min(Date.parse(e.end_at), Date.parse(until))]).sort((a, b) => a[0] - b[0]);
  let t = 0, end = -Infinity;
  for (const [s, e] of iv) {
    t += Math.max(0, e - Math.max(s, end));
    end = Math.max(end, e);
  }
  return Math.round(t / 60000 / 15) * 15;
}
const K_BUSY = `export default function main({ busy }, p) {
  const iv = busy(p).rows().map(r => [Math.max(+r.start_at, +p.from), Math.min(+r.end_at, +p.until)]).sort((a, b) => a[0] - b[0]);
  let t = 0, end = -Infinity;
  for (const [s, e] of iv) { t += Math.max(0, e - Math.max(s, end)); end = Math.max(end, e); }
  return Math.round(t / 60000 / 15) * 15;
}`;
for (let i = 0; i < 12; i++) {
  const from = iso(D0 + i * DAY), until = iso(D0 + (i + 1) * DAY);
  add({ id: `vault-busy-minutes-${i}`, domain: "personal", holder: "vault", question: `How many minutes is Alice busy on ${from.slice(0, 10)} (overlaps counted once, rounded to 15)?`,
    remit: { mode: "kernel", reads: { busy: BUSY }, source: K_BUSY, params: { from, until }, returns: INT(1440), purpose: "scheduling" },
    baseline: { ...ev(from, until), answer: ([e]) => busyMinutes(e, from, until) }, truth: (d) => busyMinutes(d.events, from, until), check: same });
}
function firstSlot(es: any[], from: string, until: string, minutes: number): string | null {
  const taken = es.filter(live).filter((e) => overl(e, from, until)).map((e) => [Date.parse(e.start_at), Date.parse(e.end_at)]).sort((a, b) => a[0] - b[0]);
  for (let day = Date.parse(from); day < Date.parse(until); day += DAY) {
    let t = day + 9 * H;
    const close = day + 18 * H;
    for (const [s, e] of taken) {
      if (e <= t || s >= close) continue;
      if (s - t >= minutes * 60000) return iso(t);
      t = Math.max(t, Math.ceil(e / 900000) * 900000);
    }
    if (close - t >= minutes * 60000) return iso(t);
  }
  return null;
}
const K_FIRST = `export default function main({ busy }, p) {
  const H = 3600000, need = p.minutes * 60000;
  const taken = busy(p).rows().map(r => [+r.start_at, +r.end_at]).sort((a, b) => a[0] - b[0]);
  for (let day = +p.from; day < +p.until; day += 24 * H) {
    let t = day + 9 * H; const close = day + 18 * H;
    for (const [s, e] of taken) {
      if (e <= t || s >= close) continue;
      if (s - t >= need) return new Date(t);
      t = Math.max(t, Math.ceil(e / 900000) * 900000);
    }
    if (close - t >= need) return new Date(t);
  }
  return null;
}`;
for (let i = 0; i < 12; i++) {
  const minutes = [30, 45, 60, 90, 120, 180][i % 6];
  const from = iso(D0 + i * DAY), until = iso(D0 + (i + 4) * DAY);
  add({ id: `vault-first-slot-${i}`, domain: "personal", holder: "vault", question: `When does the first free ${minutes}-minute slot between 09:00 and 18:00 UTC start, from ${from.slice(0, 10)} to ${until.slice(0, 10)}?`,
    remit: { mode: "kernel", reads: { busy: BUSY }, source: K_FIRST, params: { from, until, minutes }, returns: { optional: { timestamp: { min: "$from", max: "$until", granularity: "15m" } } }, purpose: "scheduling", post: (v: any) => (v === null ? null : iso(Date.parse(v))) },
    baseline: { ...ev(from, until), answer: ([e]) => firstSlot(e, from, until, minutes) }, truth: (d) => firstSlot(d.events, from, until, minutes), check: same });
}

// ------------------------------------------------------ enterprise analytics
const REGIONS = ["AMER", "APAC", "EMEA", "LATAM"], SEGS = ["smb", "mid", "enterprise"], STAGES = ["won", "lost", "open"];
const K = 20;
const acct = (args: any = {}) => ({ calls: [{ tool: "list_accounts", args }] });
function group(rows: any[], key: string, f: (rs: any[]) => number) {
  const m = new Map<string, any[]>();
  for (const r of rows) m.set(r[key], [...(m.get(r[key]) ?? []), r]);
  return Object.fromEntries([...m].filter(([, rs]) => new Set(rs.map((r) => r.account_id)).size >= K).map(([k, rs]) => [k, f(rs)]));
}
const sum = (c: string) => (rs: any[]) => rs.reduce((s, r) => s + Number(r[c]), 0);
const byKey = (key: string, v: string) => (rows: any[]) => Object.fromEntries(rows.map((r) => [r[key], r[v]]));
for (const [i, r] of REGIONS.entries()) {
  const f = (a: any[]) => group(a.filter((x) => x.region === r), "segment", sum("arr"));
  add({ id: `crm-arr-segments-${r}`, domain: "enterprise", holder: "crm", question: `Total ARR per segment in ${r} (nearest $100).`,
    remit: { mode: "query", sql: `SELECT segment, SUM(arr) AS v FROM crm.accounts WHERE region = $region GROUP BY segment`, params: { region: r }, returns: { list: { max: 3, of: { struct: { segment: { enum: SEGS }, v: { float: { min: 0, max: 1e10, precision: 100 } } } } } }, purpose: "analytics", post: byKey("segment", "v") },
    baseline: { ...acct({ region: r }), answer: ([a]) => f(a) }, truth: (d) => f(d.accounts), check: rec(0.01) });
  void i;
}
for (const s of SEGS) {
  const f = (a: any[]) => group(a.filter((x) => x.segment === s), "region", (rs) => rs.length);
  add({ id: `crm-count-regions-${s}`, domain: "enterprise", holder: "crm", question: `How many ${s} accounts are there per region?`,
    remit: { mode: "query", sql: "SELECT region, COUNT(*) AS n FROM crm.accounts WHERE segment = $seg GROUP BY region", params: { seg: s }, returns: { list: { max: 4, of: { struct: { region: { enum: REGIONS }, n: INT(100000) } } } }, purpose: "analytics", post: byKey("region", "n") },
    baseline: { ...acct(), answer: ([a]) => f(a) }, truth: (d) => f(d.accounts), check: rec(0) });
}
for (const r of REGIONS) for (const s of SEGS) {
  const f = (a: any[]) => {
    const x = a.filter((y) => y.region === r && y.segment === s);
    return x.length >= K ? sum("arr")(x) / x.length : null;
  };
  add({ id: `crm-avg-arr-${r}-${s}`, domain: "enterprise", holder: "crm", question: `Average ARR of ${s} accounts in ${r} (nearest $10; null if the group is too small to disclose).`,
    remit: { mode: "query", sql: "SELECT AVG(arr) AS v FROM crm.accounts WHERE region = $r AND segment = $s", params: { r, s }, returns: { optional: { float: { min: 0, max: 1e7, precision: 10 } } }, purpose: "analytics" },
    baseline: { ...acct({ region: r }), answer: ([a]) => f(a) }, truth: (d) => f(d.accounts), check: (a, b) => (a === null || b === null ? a === b : num(0.01)(a, b)) });
}
for (const st of STAGES) for (const since of ["2025-06-01", "2025-12-01", "2026-03-01"]) {
  const from = `${since}T00:00:00Z`;
  const f = (ds: any[]) => {
    const w = ds.filter((x) => x.stage === st && x.closed_at >= from);
    return new Set(w.map((x) => x.account_id)).size >= K ? w.length : null;
  };
  add({ id: `crm-deals-${st}-${since}`, domain: "enterprise", holder: "crm", question: `How many deals with stage ${st} have closed_at on or after ${since} (null if too few accounts)?`,
    remit: { mode: "query", sql: "SELECT COUNT(*) AS n FROM crm.deals WHERE stage = $st AND closed_at >= $since", params: { st, since: from }, returns: { optional: INT(1000000) }, purpose: "analytics" },
    baseline: { calls: [{ tool: "list_deals", args: { stage: st } }], answer: ([x]) => f(x) }, truth: (d) => f(d.deals), check: same });
}
function joined(deals: any[], accounts: any[], st: string) {
  const a = new Map(accounts.map((x) => [x.account_id, x]));
  return deals.filter((d) => d.stage === st && a.has(d.account_id)).map((d) => ({ ...d, ...a.get(d.account_id) }));
}
const bothCalls = { calls: [{ tool: "list_deals", args: {} }, { tool: "list_accounts", args: {} }] };
for (const st of STAGES) for (const key of ["region", "segment"]) {
  const vals = key === "region" ? REGIONS : SEGS;
  const f = (d: any[], a: any[]) => group(joined(d, a, st), key, sum("amount"));
  add({ id: `crm-amount-${st}-${key}`, domain: "enterprise", holder: "crm", question: `Total amount of ${st} deals per ${key} (nearest $100).`,
    remit: { mode: "query", sql: `SELECT a.${key} AS k, SUM(d.amount) AS v FROM crm.deals d JOIN crm.accounts a ON a.account_id = d.account_id WHERE d.stage = $st GROUP BY a.${key}`, params: { st }, returns: { list: { max: 4, of: { struct: { k: { enum: vals }, v: { float: { min: 0, max: 1e12, precision: 100 } } } } } }, purpose: "analytics", post: byKey("k", "v") },
    baseline: { ...bothCalls, answer: ([d, a]) => f(d, a) }, truth: (d) => f(d.deals, d.accounts), check: rec(0.01) });
}
const K_BEST = `export default function main({ won, all }, p) {
  const w = new Map(won(p).rows().map(r => [r.k, r.n]));
  let best = null;
  for (const r of all(p).rows()) { const x = (w.get(r.k) ?? 0) / r.n; if (!best || x > best.x) best = { k: r.k, x }; }
  return best ? best.k : null;
}`;
for (const key of ["region", "segment"]) for (const since of ["2025-03-01", "2025-06-01", "2025-09-01", "2025-12-01"]) {
  const from = `${since}T00:00:00Z`;
  const f = (ds: any[], as: any[]) => {
    const closed = [...joined(ds, as, "won"), ...joined(ds, as, "lost")].filter((d) => d.closed_at >= from);
    const all = group(closed, key, (rs) => rs.length), won = group(closed.filter((d) => d.stage === "won"), key, (rs) => rs.length);
    let best: any = null;
    for (const k of Object.keys(all)) {
      const x = (won[k] ?? 0) / all[k];
      if (!best || x > best.x) best = { k, x };
    }
    return best?.k ?? null;
  };
  const q = (w: string) => ({ sql: `SELECT a.${key} AS k, COUNT(*) AS n FROM crm.deals d JOIN crm.accounts a ON a.account_id = d.account_id WHERE ${w} AND d.closed_at >= $since GROUP BY a.${key}`, params: { since: "timestamp" }, max_rows: 10 });
  add({ id: `crm-best-win-rate-${key}-${since}`, domain: "enterprise", holder: "crm", question: `Which ${key} has the highest win rate (won / (won + lost)) since ${since}?`,
    remit: { mode: "kernel", reads: { won: q("d.stage = 'won'"), all: q("d.stage <> 'open'") }, source: K_BEST, params: { since: from }, returns: { optional: { enum: key === "region" ? REGIONS : SEGS } }, purpose: "forecasting" },
    baseline: { ...bothCalls, answer: ([d, a]) => f(d, a) }, truth: (d) => f(d.deals, d.accounts), check: same });
}
for (const y of [2023, 2024, 2025, 2026]) for (const s of ["all", "enterprise"]) {
  const from = `${y}-01-01T00:00:00Z`, until = `${y + 1}-01-01T00:00:00Z`;
  const f = (a: any[]) => {
    const n = a.filter((x) => x.created_at >= from && x.created_at < until && (s === "all" || x.segment === s)).length;
    return n >= K ? n : null;
  };
  add({ id: `crm-new-${y}-${s}`, domain: "enterprise", holder: "crm", question: `How many ${s === "all" ? "" : "enterprise "}accounts were created in ${y} (null if fewer than 20)?`,
    remit: { mode: "query", sql: `SELECT COUNT(*) AS n FROM crm.accounts WHERE created_at >= $from AND created_at < $until${s === "all" ? "" : " AND segment = 'enterprise'"}`, params: { from, until }, returns: { optional: INT(100000) }, purpose: "analytics" },
    baseline: { ...acct(), answer: ([a]) => f(a) }, truth: (d) => f(d.accounts), check: same });
}

// ------------------------------------------------------------ documents / code
const DOCS = ["billing", "refunds", "security", "shipping"];
const docCalls = { calls: [{ tool: "list_chunks", args: {} }] };
const TOPICS: [string, string][] = [
  ["refunded", "refunds"], ["refundable", "refunds"], ["VAT", "billing"], ["invoices", "billing"], ["payment methods", "billing"], ["encrypted", "security"], ["SSO", "security"], ["incidents disclosed", "security"],
  ["customs", "shipping"], ["express shipping countries", "shipping"], ["bank transfer", "billing"], ["EU ship days", "shipping"], ["annual plans", "refunds"], ["monthly plans billing date", "refunds"], ["enterprise plan", "security"], ["recipient fees", "shipping"],
];
for (const [i, [q, doc]] of TOPICS.entries()) {
  add({ id: `docs-which-${i}`, domain: "documents", holder: "docs", question: `Which help-center document best answers a question about "${q}"?`,
    remit: { mode: "query", sql: "SELECT c.doc FROM fts('kb', $q, 1) s JOIN docs.chunks c ON c.chunk_id = s.id ORDER BY s.score DESC LIMIT 1", params: { q }, returns: { list: { max: 1, of: { struct: { doc: { enum: DOCS } } } } }, purpose: "support", post: (v: any[]) => v[0]?.doc ?? null },
    baseline: { ...docCalls, answer: () => doc }, truth: () => doc, check: same });
}
for (const doc of DOCS) {
  const n = (cs: any[]) => cs.filter((c) => c.doc === doc).length;
  add({ id: `docs-count-${doc}`, domain: "documents", holder: "docs", question: `How many passages does the ${doc} document have?`,
    remit: { mode: "query", sql: "SELECT COUNT(*) AS n FROM docs.chunks WHERE doc = $doc", params: { doc }, returns: INT(1000), purpose: "support" },
    baseline: { ...docCalls, answer: ([c]) => n(c) }, truth: (d) => n(d.chunks), check: same });
}
const WORDS = ["days", "plan", "EU", "fees", "AES", "12", "month", "bank", "72", "country", "rest", "SSO"];
for (const w of WORDS) {
  const f = (cs: any[]) => DOCS.filter((doc) => cs.some((c) => c.doc === doc && c.body.includes(w)));
  add({ id: `docs-mention-${w}`, domain: "documents", holder: "docs", question: `Which documents mention "${w}" (case-sensitive)? List in alphabetical order.`,
    remit: { mode: "query", sql: "SELECT DISTINCT doc FROM docs.chunks WHERE body LIKE $p ORDER BY doc", params: { p: `%${w}%` }, returns: { list: { max: 4, of: { struct: { doc: { enum: DOCS } } } } }, purpose: "support", post: (v: any[]) => v.map((x) => x.doc) },
    baseline: { ...docCalls, answer: ([c]) => f(c) }, truth: (d) => f(d.chunks), check: same });
}
const FACTS: [string, string, number][] = [
  ["Within how many days of purchase can annual plans be refunded?", "annual plans refunded days", 30], ["How many business days do refund requests take?", "refund requests business days", 5], ["Within how many business days do EU orders ship?", "EU orders ship business days", 3],
  ["In how many countries is express shipping available?", "express shipping countries", 12], ["Which AES key size (bits) encrypts data at rest?", "encrypted at rest AES", 256], ["Within how many hours are incidents disclosed?", "incidents disclosed hours", 72],
];
const K_NUM = `export default function main({ hit }, p) {
  for (const r of hit({ q: p.q }).rows()) { const m = /(\\d+)/.exec(r.body); if (m) return +m[1]; }
  return null;
}`;
const HIT = { sql: "SELECT c.body FROM fts('kb', $q, 3) s JOIN docs.chunks c ON c.chunk_id = s.id ORDER BY s.score DESC", params: { q: "string" }, max_rows: 3 };
for (const [i, [question, q, n]] of FACTS.entries()) {
  add({ id: `docs-fact-${i}`, domain: "documents", holder: "docs", question,
    remit: { mode: "kernel", reads: { hit: HIT }, source: K_NUM, params: { q }, returns: { optional: INT(100000) }, purpose: "support" },
    baseline: { ...docCalls, answer: () => n }, truth: () => n, check: same });
}
for (let i = 0; i < 12; i++) {
  const min = 30 + i * 3;
  const f = (cs: any[]) => cs.filter((c) => c.body.length >= min).length;
  add({ id: `docs-length-${i}`, domain: "documents", holder: "docs", question: `How many passages have at least ${min} characters?`,
    remit: { mode: "query", sql: "SELECT COUNT(*) AS n FROM docs.chunks WHERE LENGTH(body) >= $min", params: { min }, returns: INT(1000), purpose: "support" },
    baseline: { ...docCalls, answer: ([c]) => f(c) }, truth: (d) => f(d.chunks), check: same });
}

// ----------------------------------------------------------------- B2B overlap
const CUST = { calls: [{ tool: "list_customers", args: {} }] };
const COUNTRIES = ["DE", "FR", "GB", "JP", "PT", "US", "BR", "ES", "IT", "NL"];
const K_OVER = `export default function main({ c }, p) {
  const s = new Set(); for (const r of c({}).rows()) if (!p.country || r.country === p.country) s.add(r.email_sha256);
  let n = 0; for (const h of p.mine) if (s.has(h)) n++; return n;
}`;
const OVER = { c: { sql: "SELECT email_sha256, country FROM crm.customers", max_rows: 10000 } };
const LIM = { fuel: 900_000_000, wall_ms: 8000, memory_bytes: 134217728 };
for (let i = 0; i < 25; i++) {
  const [a, b] = [i * 16, Math.min(400, i * 16 + 40 + i * 8)];
  const f = (d: Data, cs: any[]) => {
    const s = new Set(cs.map((c) => c.email_sha256));
    return d.companyA.slice(a, b).filter((e) => s.has(sha(e))).length;
  };
  add({ id: `b2b-slice-${i}`, domain: "b2b", holder: "b2b", question: `How many of Company A's customers #${a}–${b} are also Company B's customers?`,
    remit: { mode: "kernel", reads: OVER, source: K_OVER, params: { mine: `$companyA:${a}:${b}` }, returns: INT(10000), limits: LIM, purpose: "overlap" },
    baseline: { ...CUST, answer: ([c], d) => f(d, c) }, truth: (d) => f(d, d.customers), check: same });
}
for (const country of COUNTRIES) {
  const f = (d: Data, cs: any[]) => {
    const s = new Set(cs.filter((c) => c.country === country).map((c) => c.email_sha256));
    return d.companyA.filter((e) => s.has(sha(e))).length;
  };
  add({ id: `b2b-country-${country}`, domain: "b2b", holder: "b2b", question: `How many of Company A's customers are Company B customers in ${country}?`,
    remit: { mode: "kernel", reads: OVER, source: K_OVER, params: { mine: "$companyA:0:400", country }, returns: INT(10000), limits: LIM, purpose: "overlap" },
    baseline: { ...CUST, answer: ([c], d) => f(d, c) }, truth: (d) => f(d, d.customers), check: same });
}
const K_RATE = K_OVER.replace("return n;", "return Math.round(100 * n / p.mine.length);");
for (let i = 0; i < 10; i++) {
  const [a, b] = [i * 40, (i + 1) * 40];
  const f = (d: Data, cs: any[]) => {
    const s = new Set(cs.map((c) => c.email_sha256));
    return Math.round((100 * d.companyA.slice(a, b).filter((e) => s.has(sha(e))).length) / (b - a));
  };
  add({ id: `b2b-rate-${i}`, domain: "b2b", holder: "b2b", question: `What percentage of Company A's customers #${a}–${b} are shared with Company B (rounded)?`,
    remit: { mode: "kernel", reads: OVER, source: K_RATE, params: { mine: `$companyA:${a}:${b}` }, returns: INT(100), limits: LIM, purpose: "overlap" },
    baseline: { ...CUST, answer: ([c], d) => f(d, c) }, truth: (d) => f(d, d.customers), check: same });
}
const K_TOP = `export default function main({ c }, p) {
  const m = new Map(c({}).rows().map(r => [r.email_sha256, r.country])); const n = {};
  for (const h of p.mine) { const k = m.get(h); if (k) n[k] = (n[k] ?? 0) + 1; }
  const top = Object.entries(n).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))[0]; return top ? top[0] : null;
}`;
for (let i = 0; i < 5; i++) {
  const [a, b] = [i * 80, (i + 1) * 80];
  const f = (d: Data, cs: any[]) => {
    const m = new Map(cs.map((c) => [c.email_sha256, c.country]));
    const n: Record<string, number> = {};
    for (const e of d.companyA.slice(a, b)) {
      const k = m.get(sha(e));
      if (k) n[k] = (n[k] ?? 0) + 1;
    }
    return Object.entries(n).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1))[0]?.[0] ?? null;
  };
  add({ id: `b2b-top-country-${i}`, domain: "b2b", holder: "b2b", question: `Among Company A customers #${a}–${b} shared with Company B, which country (at B) is most common (ties: alphabetical)?`,
    remit: { mode: "kernel", reads: OVER, source: K_TOP, params: { mine: `$companyA:${a}:${b}` }, returns: { optional: { string: { max_len: 2, charset: "alpha" } } }, limits: LIM, purpose: "overlap" },
    baseline: { ...CUST, answer: ([c], d) => f(d, c) }, truth: (d) => f(d, d.customers), check: same });
}

export const TASKS_V1: Task[] = out;
export const ALL_TASKS: Task[] = [...V0, ...out];

/** Authoring study: 60 tasks, 15 per domain, spread over every family. */
export function authoringTasks(): Task[] {
  const pick = (dom: string) => {
    const all = out.filter((t) => t.domain === dom);
    const fam = new Map<string, Task[]>();
    for (const t of all) {
      const k = t.id.split("-").slice(0, 2).join("-");
      fam.set(k, [...(fam.get(k) ?? []), t]);
    }
    const res: Task[] = [];
    for (let i = 0; res.length < 15; i++) for (const ts of fam.values()) if (ts[i] && res.length < 15) res.push(ts[i]);
    return res;
  };
  return ["personal", "enterprise", "documents", "b2b"].flatMap(pick);
}
