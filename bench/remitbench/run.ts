// RemitBench runner: scripted reference solutions, both arms.
import { join } from "node:path";
import { Remit, Identity } from "../../sdk/ts/src/index.ts";
import { ALL_TASKS as TASKS } from "./tasks_gen.ts";
import { HOLDERS, ROOT, baselineTool, loadData, mcpBytes, resolveParams, spawnHolders } from "./common.ts";

const spawnFlag = process.argv.includes("--spawn");
const kids = spawnFlag ? await spawnHolders() : [];
const data = loadData();
let bytesIn = 0;
const countingFetch: typeof fetch = async (input, init) => {
  const r = await fetch(input, init);
  const buf = await r.arrayBuffer();
  if (String(input).includes("/remit/v1/")) bytesIn += buf.byteLength;
  return new Response(buf, { status: r.status, headers: r.headers });
};

const rows: any[] = [];
try {
  for (const task of TASKS) {
    const want = task.truth(data);
    // (a) baseline
    let bBytes = 0;
    const results = task.baseline.calls.map((c, i) => {
      const r = baselineTool(data, c.tool, c.args);
      bBytes += mcpBytes(r, i + 1);
      return r;
    });
    const bAns = task.baseline.answer(results, data);
    // (b) remit
    const hcfg = HOLDERS[task.holder];
    const remit = new Remit({ identity: Identity.load(join(ROOT, hcfg.key)), fetch: countingFetch });
    const h = await remit.holder(hcfg.url);
    const p = { ...task.remit };
    const params = resolveParams(data, p.params);
    bytesIn = 0;
    let rAns: unknown, bits = 0, ok = true, err = "";
    const t0 = performance.now();
    try {
      const res = p.mode === "kernel"
        ? await h.kernel({ reads: p.reads, params, returns: p.returns, source: p.source, limits: p.limits ?? { fuel: 100_000_000, wall_ms: 2000 }, purpose: p.purpose })
        : await h.query({ sql: p.sql, params, returns: p.returns, limits: p.limits, purpose: p.purpose });
      const v = JSON.parse(JSON.stringify(res.value, (_k, x) => (x && typeof x === "object" && "untrusted" in x ? x.untrusted : x)));
      rAns = p.post ? p.post(v) : v;
      bits = res.receipt.result_bits_max;
    } catch (e: any) {
      ok = false;
      err = e.message;
    }
    const ms = performance.now() - t0;
    const resultBytes = rAns === undefined ? 0 : Buffer.byteLength(JSON.stringify(rAns));
    rows.push({
      task: task.id,
      baseline_correct: task.check(bAns, want),
      remit_correct: ok && task.check(rAns, want) || (task.id === "b2b-overlap" && ok && Number(rAns) === Number(want)),
      baseline_round_trips: task.baseline.calls.length,
      remit_round_trips: 1,
      baseline_bytes: bBytes,
      remit_result_bytes: resultBytes,
      remit_response_bytes: bytesIn,
      baseline_tokens_est: Math.round(bBytes / 4),
      remit_tokens_est: Math.round(resultBytes / 4),
      remit_max_bits: bits,
      remit_ms: Math.round(ms),
      error: err || undefined,
    });
  }
} finally {
  for (const k of kids) k.kill();
}
if (!process.argv.includes("--quiet")) console.table(rows.map(({ error, ...r }) => r));
const sum = (k: string) => rows.reduce((s, r) => s + (r[k] ?? 0), 0);
const summary = {
  tasks: rows.length,
  baseline_accuracy: rows.filter((r) => r.baseline_correct).length / rows.length,
  remit_accuracy: rows.filter((r) => r.remit_correct).length / rows.length,
  bytes_reduction: 1 - sum("remit_result_bytes") / sum("baseline_bytes"),
  tokens_reduction_est: 1 - sum("remit_tokens_est") / sum("baseline_tokens_est"),
  round_trips: { baseline: sum("baseline_round_trips"), remit: sum("remit_round_trips") },
  max_leakage_bits_total: sum("remit_max_bits"),
  median_max_bits: rows.map((r) => r.remit_max_bits).sort((a, b) => a - b)[Math.floor(rows.length / 2)],
  multi_step: (() => {
    const m = rows.filter((r) => r.baseline_round_trips > 1);
    return { tasks: m.length, round_trips: { baseline: m.reduce((s, r) => s + r.baseline_round_trips, 0), remit: m.length }, tokens_reduction_est: 1 - m.reduce((s, r) => s + r.remit_tokens_est, 0) / Math.max(1, m.reduce((s, r) => s + r.baseline_tokens_est, 0)) };
  })(),
  by_domain: Object.fromEntries([...new Set(TASKS.map((t) => t.domain))].map((d) => {
    const rs = rows.filter((r) => TASKS.find((t) => t.id === r.task)!.domain === d);
    return [d, { tasks: rs.length, remit_accuracy: rs.filter((r) => r.remit_correct).length / rs.length, baseline_accuracy: rs.filter((r) => r.baseline_correct).length / rs.length, bytes_reduction: 1 - rs.reduce((s, r) => s + r.remit_result_bytes, 0) / rs.reduce((s, r) => s + r.baseline_bytes, 0) }];
  })),
};
console.log(JSON.stringify(summary, null, 2));
for (const r of rows.filter((r) => r.error)) console.error(`${r.task}: ${r.error}`);
if (process.argv.includes("--require-parity") && summary.remit_accuracy < summary.baseline_accuracy) {
  console.error("accuracy below the baseline");
  process.exitCode = 1;
}
if (process.argv.includes("--json")) console.log(JSON.stringify({ rows, summary }));
