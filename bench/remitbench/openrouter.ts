// An authoring-study author backed by OpenRouter. Reads a prompt on stdin, prints the reply.
//   OPENROUTER_API_KEY=... REMITBENCH_MAX_USD=7 node bench/remitbench/openrouter.ts <model>
// Spend is logged to REMITBENCH_SPEND_LOG; no call is made once REMITBENCH_MAX_USD is reached.
import { appendFileSync, existsSync, readFileSync } from "node:fs";

const model = process.argv[2];
const log = process.env.REMITBENCH_SPEND_LOG ?? "remitbench-spend.jsonl";
const cap = Number(process.env.REMITBENCH_MAX_USD ?? 1);

function spentSoFar(): number {
  if (!existsSync(log)) return 0;
  const lines = readFileSync(log, "utf8").split("\n").filter((l) => l.length > 0);
  return lines.reduce((sum, l) => sum + (JSON.parse(l).usd ?? 0), 0);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const spent = spentSoFar();
if (spent >= cap) {
  console.error(`spending cap reached: ${spent.toFixed(2)} of ${cap} USD`);
  process.exit(3);
}

const prompt = readFileSync(0, "utf8");
for (let attempt = 0; attempt < 4; attempt++) {
  let res: Response;
  try {
    res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: { authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({
        model,
        max_tokens: 6000,
        reasoning: { effort: "low" },
        usage: { include: true },
        messages: [{ role: "user", content: prompt }],
      }),
      signal: AbortSignal.timeout(200_000),
    });
  } catch (e) {
    console.error(String(e));
    await sleep(3000);
    continue;
  }
  if (!res.ok) {
    console.error(`http ${res.status}: ${(await res.text()).slice(0, 200)}`);
    if (res.status !== 429 && res.status < 500) process.exit(4);
    await sleep(3000 * 2 ** attempt);
    continue;
  }
  const j = await res.json();
  appendFileSync(log, JSON.stringify({ model, usd: j.usage?.cost ?? 0, in: j.usage?.prompt_tokens, out: j.usage?.completion_tokens }) + "\n");
  console.log(j.choices?.[0]?.message?.content ?? "");
  process.exit(0);
}
process.exit(5);
