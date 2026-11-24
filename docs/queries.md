# Write a query

Use query mode when the answer can be expressed as one SQL query. Start from a holder’s catalog and request the smallest useful result.

The examples below continue the `finance` holder and `t` import from the [TypeScript quickstart](quickstart-typescript.md).

## Use catalog names and enums

```ts
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
```

Relations use `source.table` names. A hidden column does not exist from the sender’s point of view. Published enums let the sender bound a field without guessing the set of possible values.

## Bind values as parameters

Keep SQL structure separate from the changing inputs:

```ts
const answer = await finance.query({
  sql: `SELECT region, COUNT(*) AS accounts
        FROM crm.accounts WHERE arr >= $floor
        GROUP BY region ORDER BY region`,
  params: { floor: 100000.5 },
  returns: t.list(t.struct({
    region: t.enum(...finance.enums("crm.accounts.region")),
    accounts: t.int({ min: 0, max: 100000 }),
  }), { max: 4 }),
  purpose: "analytics",
});
```

Filtering may leave fewer than the required number of privacy units in a group. The holder enforces that rule in the plan. An empty result does not entitle the sender to relax the holder’s policy.

## Respect the SQL profile

Remit supports a single `SELECT`, joins, grouping, ordering, subqueries, non-recursive CTEs and allowlisted deterministic functions. It does not allow writes, DDL, arbitrary functions, recursive CTEs, or functions such as `now()` and `random()`. Pass time explicitly as a parameter.

Use named parameters such as `$floor`, not positional `$1` parameters. Set a return list or table bound that can contain the legitimate answer. Exceeding a row cap produces `limit_exceeded`, rather than silently returning an incomplete answer.

When one query is not enough, [declare multiple reads in a kernel](kernels.md). See the [SQL specification](../spec/sql.md) for the complete dialect, search functions and diagnostic codes.
