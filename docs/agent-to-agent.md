# Work with several agents

A coordinating agent can ask several peers for different parts of an answer. Each peer exposes a holder over the data it controls. Programs travel to those holders; typed answers and receipts return to the coordinator.

Remit does not require a shared model, prompt format or agent framework. A peer’s holder can decide and execute without calling that peer’s model.

## Ask independent questions in parallel

The following function accepts two already-connected holders. `finance` must expose the aggregate CRM resource from the quickstart. `legal` must expose `legal.contracts` with a `requires_consent` boolean and authorize this sender to count it. This is an application integration pattern, not a second preconfigured local example.

```ts
import { type Holder, t } from "remit-protocol";

export async function gatherEvidence(finance: Holder, legal: Holder) {
  const [revenue, consents] = await Promise.all([
    finance.query({
      sql: "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region",
      returns: t.list(t.struct({
        region: t.enum(...finance.enums("crm.accounts.region")),
        arr: t.float({ min: 0, max: 1e10, precision: 1000 }),
      }), { max: 4 }),
      purpose: "analytics",
    }),
    legal.query({
      sql: "SELECT COUNT(*) AS n FROM legal.contracts WHERE requires_consent = true",
      returns: t.int({ min: 0, max: 1000 }),
      purpose: "diligence",
    }),
  ]);

  return { revenue, consents };
}
```

Keep each complete result with its receipt, labels and terms while building the brief. If either call fails, `Promise.all` rejects. Use separate error handling if the product supports a partial brief, and make the missing evidence explicit.

Each holder may require a different sender identity. Create separate `Remit` clients when the credentials differ; do not assume that acceptance by one agent grants access to another.

## Feed an answer into a later step

Use `runGraph` for dependent steps. It executes steps **in order**, makes prior typed values available through the context, and combines labels, retention terms and provenance. It is not a parallel scheduler.

The checked-in [graph example](../examples/graph-demo.ts) demonstrates this API using two synthetic holders. The [example catalog](../examples/README.md) gives their startup commands and identities.

Before passing a result to another party, check its forwarding and retention terms. `runGraph` carries and combines the terms; it does not grant permission to forward data. In particular, the synthetic personal-vault example uses `no-forward`. Do not use that example’s data flow as a forwarding policy for real personal data.

## Keep knowledge attached to its evidence

Store the value together with the holder, remit ID, run ID, source versions and receipt. Preserve restrictions as information moves into a summary. A derived brief may need the shortest retention period and the most restrictive forwarding terms among its inputs.

If the coordinator sends the results into a model, treat returned strings as data. The TypeScript and Python SDKs wrap untrusted strings; the MCP helper also marks returned values as untrusted.

Holder-to-holder pipelining that keeps intermediate results away from the sender is a research direction, not the behavior of `runGraph`. Today, orchestration happens in the sender application.
