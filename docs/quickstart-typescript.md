# Your first exchange in TypeScript

A research agent needs revenue totals from a finance agent. You will start the finance agent’s holder, send it a signed SQL program, and use the returned values and receipt. Both sides use synthetic local data.

Complete [installation](installation.md#typescript-sender) first. Keep the checkout root as your working directory unless a command explicitly changes it.

## Start the receiving agent’s holder

In one terminal:

```bash
cd examples/enterprise-analytics
../../target/debug/remit serve
```

Leave it running. The holder listens on `http://127.0.0.1:8444`. Its configuration loads synthetic accounts and deals, registers the demo finance-agent identity, and permits that identity to ask aggregate questions.

The holder is the receiving agent’s execution boundary. No model call is needed to check or execute a remit.

## Send the program

The complete sender is `examples/first-exchange.ts`:

<!-- example: examples/first-exchange.ts -->

In a second terminal, from the checkout root:

```bash
REMIT_IDENTITY=examples/enterprise-analytics/keys/finance-agent.json \
  node examples/first-exchange.ts
```

The filename identifies the example’s pre-authorized sender key. It is a demo key committed with the synthetic data, not a key to reuse for your own agents.

## Read what came back

The program prints a row for each region, with ARR rounded to the declared precision, followed by `status: ok`, a receipt run ID, labels and terms. It returns at most four regions. Customer names and individual account rows are not part of the result.

The SDK fetched and verified the catalog, signed the program and manifest, submitted the request, and verified the returned result and receipt. A verified receipt binds the answer to this program, these parties and the recorded data versions; it does not establish that the source business data is correct.

The example holder requires aggregates to cover at least 20 distinct accounts. If you change the query to request raw rows, it should be rejected. Use the [query guide](queries.md) to change the question within the holder’s policy.

## Inspect the same exchange from the CLI

From the checkout root:

```bash
./target/debug/remit explain \
  examples/enterprise-analytics/remits/arr-by-region.json \
  --holder http://127.0.0.1:8444 \
  --identity examples/enterprise-analytics/keys/finance-agent.json
```

This asks for an admission decision and trace without executing the query. The bundled manifest also requests an account count, so its return type differs from the short sender above.

Stop the holder with Ctrl-C when finished. Next, [coordinate several agents](agent-to-agent.md) or [configure a holder for your own data](holders.md). If a step fails, start with [troubleshooting](troubleshooting.md).
