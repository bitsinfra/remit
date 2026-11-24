// Company A learns how many of its 400 customers Company B also has.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Remit, t } from "../../sdk/ts/src/index.ts";

const remit = new Remit({ identity: await Remit.identity.fromEnv() });
const b = await remit.holder(process.env.HOLDER ?? "http://127.0.0.1:8445");
const mine = readFileSync(new URL("./data/company-a-list.txt", import.meta.url), "utf8").trim().split("\n").map((e) => createHash("sha256").update(e.trim().toLowerCase()).digest("hex"));
const r = await b.kernel<number>({
  reads: { customers: { sql: "SELECT email_sha256 FROM crm.customers", max_rows: 10000 } },
  params: { mine },
  returns: t.int({ min: 0, max: 10000 }),
  source: readFileSync(new URL("./kernels/overlap.js", import.meta.url), "utf8"),
  limits: { fuel: 200_000_000, wall: "2s", memory: "64MiB" },
  purpose: "overlap",
});
console.log(`overlap: ${r.value} of ${mine.length} (≤ ${r.receipt.result_bits_max} bits left Company B)`);
