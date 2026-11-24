import { Remit, t } from "../sdk/ts/src/index.ts";

const remit = new Remit({ identity: await Remit.identity.fromEnv() });
const finance = await remit.holder(process.env.HOLDER ?? "http://127.0.0.1:8444");

const answer = await finance.query({
  sql: `SELECT region, SUM(arr) AS arr
        FROM crm.accounts
        GROUP BY region ORDER BY region`,
  returns: t.list(t.struct({
    region: t.enum(...finance.enums("crm.accounts.region")),
    arr: t.float({ min: 0, max: 1e10, precision: 1000 }),
  }), { max: 4 }),
  purpose: "analytics",
});

console.table(answer.value);
console.log("status:", answer.status);
console.log("receipt:", answer.receipt.run_id);
console.log("labels:", answer.labels);
console.log("terms:", answer.terms);
