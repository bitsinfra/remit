// Authoring study harness: 60 tasks x {query, kernel} per author. An author
// is any external command that reads a prompt on stdin and prints a program
// JSON on stdout (an LLM wrapper). Repeat --author to compare models.
//   node bench/remitbench/author.ts --author "name=cmd args" [--author ...]
//        [--spawn] [--repairs 2] [--no-examples] [--no-stats] [--limit N] [--out file.json]
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { Remit, Identity, typesDts, RemitError } from "../../sdk/ts/src/index.ts";
import { authoringTasks } from "./tasks_gen.ts";
import { HOLDERS, ROOT, loadData, resolveParams, spawnHolders } from "./common.ts";

const arg = (n: string) => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const authors = process.argv.flatMap((a, i) => (a === "--author" ? [process.argv[i + 1]] : [])).map((a) => {
  const m = /^([\w.-]+)=(.*)$/s.exec(a);
  return m ? { name: m[1], cmd: m[2] } : { name: a.split(" ")[0], cmd: a };
});
if (!authors.length) {
  console.error("usage: author.ts --author 'name=<command>' [--author …] [--spawn] [--repairs N] [--no-examples] [--no-stats] [--limit N] [--out f]");
  process.exit(2);
}
const flag = (n: string) => process.argv.includes(`--${n}`);
const maxRepairs = Number(arg("repairs") ?? 2);
const kids = process.argv.includes("--spawn") ? await spawnHolders() : [];
const data = loadData();

const FORMAT = `Return exactly one valid JSON object, with no Markdown. Example shapes:
{"mode":"query","sql":"SELECT COUNT(*) AS n FROM app.items WHERE amount >= $min","params":{"min":1},"returns":{"int":{"min":0,"max":100}},"purpose":"analytics"}
{"mode":"kernel","reads":{"items":{"sql":"SELECT id FROM app.items WHERE amount >= $min","params":{"min":"int"},"max_rows":100}},"source":"export default function main({ items }, params) { return items(params).rows().length; }","params":{"min":1},"returns":{"int":{"min":0,"max":100}},"purpose":"analytics"}
Use the catalog's tables, columns and purposes. Result types are bounded RT declarations. For example:
"bool", {"float":{"min":0,"max":100,"precision":0.1}}, {"enum":["yes","no"]}, {"string":{"max_len":32}}, {"optional":{"timestamp":{"min":"$from","max":"$until","granularity":"15m"}}}, {"list":{"max":3,"of":{"struct":{"count":{"int":{"min":0,"max":100}}}}}}.
Each kernel read is a function: use reads.name(params).rows() (or reads.name({}).rows() without params).
SQL uses one SELECT with named parameters, non-recursive CTEs, and deterministic functions. Set operations (UNION, INTERSECT, EXCEPT), VALUES, generate_series, now() and random() are outside the profile. For a boolean about matching rows, use SELECT COUNT(*) > 0 or SELECT COUNT(*) = 0 with a WHERE filter.`;

function ask(cmd: string, prompt: string): any {
  const r = spawnSync("sh", ["-c", cmd], { input: prompt, encoding: "utf8", maxBuffer: 1 << 24, timeout: 300_000 });
  const m = /\{[\s\S]*\}/.exec(r.stdout ?? "");
  if (!m) throw new Error(`author produced no JSON: ${r.stderr?.slice(0, 200)}`);
  return JSON.parse(m[0]);
}

const tasks = authoringTasks().slice(0, Number(arg("limit") ?? 60));
const results: any[] = [];
try {
  for (const author of authors) for (const mode of ["query", "kernel"] as const) for (const task of tasks) {
    const hcfg = HOLDERS[task.holder];
    const h = await new Remit({ identity: Identity.load(join(ROOT, hcfg.key)) }).holder(hcfg.url);
    const ctx = `Holder ${h.id}\nPolicy hints:\n${h.catalog.policy_hints.join("\n")}\nPurposes: ${h.catalog.purposes.join(", ")}\nTypes:\n${typesDts(h.catalog)}`
      + (flag("no-examples") ? "" : `\nExamples:\n${JSON.stringify(h.catalog.examples).slice(0, 4000)}`)
      + (flag("no-stats") ? "" : `\nStatistics profiles:\n${JSON.stringify(h.catalog.stats).slice(0, 3000)}`);
    // Params the author cannot write itself (large value lists) are bound here.
    const bound = Object.entries(task.remit.params ?? {}).filter(([, v]) => String(v).startsWith("$companyA"));
    let prompt = `${ctx}\n\nTask: ${task.question}\nYou must use mode "${mode}".\n${bound.length ? `Params provided at run time: ${bound.map(([k]) => `"${k}": array of sha256 email hashes`).join(", ")}\n` : ""}\n${FORMAT}`;
    const tokens = { prompt: 0, reply: 0 };
    let repairs = 0, admitted = false, correct = false, firstTry = false, firstCorrect = false, lastCode = "";
    for (; repairs <= maxRepairs; repairs++) {
      tokens.prompt += Math.round(prompt.length / 4);
      let prog: any;
      try {
        prog = ask(author.cmd, prompt);
      } catch (e: any) {
        prompt += `\n\nYour previous reply was not valid JSON (${e.message}). ${FORMAT}`;
        lastCode = "not-json";
        continue;
      }
      tokens.reply += Math.round(JSON.stringify(prog).length / 4);
      const params = { ...(prog.params ?? {}), ...resolveParams(data, Object.fromEntries(bound)) };
      try {
        if (prog.mode !== mode) throw new Error(`mode must be "${mode}"`);
        const res = mode === "kernel"
          ? await h.kernel({ reads: prog.reads, params, returns: prog.returns, source: prog.source, limits: prog.limits, purpose: prog.purpose })
          : await h.query({ sql: prog.sql, params, returns: prog.returns, limits: prog.limits, purpose: prog.purpose });
        admitted = true;
        const v = JSON.parse(JSON.stringify(res.value, (_k, x) => (x && typeof x === "object" && "untrusted" in x ? x.untrusted : x)));
        correct = equivalent(task, v);
        if (repairs === 0) {
          firstTry = true;
          firstCorrect = correct;
        }
        break;
      } catch (e: any) {
        const diags = e instanceof RemitError ? (e.diagnostics.length ? e.diagnostics : [{ message: `status ${e.response?.status}` }]) : [{ message: e.message }];
        lastCode = (diags[0] as any).code ?? "error";
        prompt += `\n\nPrevious program:\n${JSON.stringify(prog)}\n\nDiagnostics to resolve:\n${JSON.stringify(diags, null, 2)}\nReply with the corrected program as JSON only.`;
      }
    }
    results.push({ author: author.name, mode, task: task.id, domain: task.domain, first_try_admitted: firstTry, first_try_correct: firstCorrect, admitted, correct, repairs: admitted ? repairs : null, last_code: lastCode || null, ...tokens });
    console.error(`${author.name} ${mode} ${task.id}: ${admitted ? (correct ? "correct" : "wrong") : `not admitted (${lastCode})`} in ${Math.min(repairs + 1, maxRepairs + 1)} attempt(s)`);
  }
} finally {
  for (const k of kids) k.kill();
}

/** Accept any reasonable shape: scalars, one-field structs/lists, key→value lists. */
function equivalent(task: (typeof tasks)[number], v: any): boolean {
  const want = task.truth(data);
  const forms: any[] = [v];
  const post = task.remit.post;
  if (post) {
    try {
      forms.push(post(v));
    } catch {
      /* different shape */
    }
  }
  const unwrap = (x: any): any => {
    if (Array.isArray(x) && x.length === 1) return unwrap(x[0]);
    if (x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).length === 1) return unwrap(Object.values(x)[0]);
    return x;
  };
  forms.push(unwrap(v));
  if (Array.isArray(v) && v.every((r) => r && typeof r === "object")) {
    forms.push(v.map((r) => unwrap(r)));
    if (v.every((r) => Object.keys(r).length === 2)) {
      forms.push(Object.fromEntries(v.map((r) => Object.values(r) as [string, unknown])));
      forms.push(Object.fromEntries(v.map((r) => (Object.values(r) as unknown[]).reverse() as [string, unknown])));
    }
  }
  if (Array.isArray(v) && v.length === 0) forms.push(null);
  return forms.some((f) => {
    try {
      return task.check(f, want);
    } catch {
      return false;
    }
  });
}

const rate = (rs: any[], f: (r: any) => boolean) => (rs.length ? Math.round((1000 * rs.filter(f).length) / rs.length) / 1000 : null);
const summary = authors.flatMap((a) => ["query", "kernel", "all"].map((mode) => {
  const rs = results.filter((r) => r.author === a.name && (mode === "all" || r.mode === mode));
  return {
    author: a.name, mode, n: rs.length,
    first_try_admission: rate(rs, (r) => r.first_try_admitted), first_try_correct: rate(rs, (r) => r.first_try_correct),
    admitted_within_repairs: rate(rs, (r) => r.admitted), correct_within_repairs: rate(rs, (r) => r.admitted && r.correct),
    mean_repairs: rs.length ? rs.filter((r) => r.repairs !== null).reduce((s, r) => s + r.repairs, 0) / Math.max(1, rs.filter((r) => r.repairs !== null).length) : null,
  };
}));
console.table(summary);
if (arg("out")) writeFileSync(arg("out")!, JSON.stringify({ date: new Date().toISOString(), options: process.argv.slice(2), summary, results }, null, 1));
