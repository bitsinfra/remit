// A non-LLM author that replies with RemitBench's own reference programs. It
// checks the authoring harness end to end; it says nothing about models.
import { readFileSync } from "node:fs";
import { authoringTasks } from "./tasks_gen.ts";
const prompt = readFileSync(0, "utf8");
const t = authoringTasks().find((x) => prompt.includes(`Task: ${x.question}\n`));
console.log(JSON.stringify(t ? { ...t.remit, params: Object.fromEntries(Object.entries(t.remit.params ?? {}).filter(([, v]) => !String(v).startsWith("$"))) } : {}));
