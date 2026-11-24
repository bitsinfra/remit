# Your first exchange in Python

Send a signed program to a finance agent’s holder and receive annual recurring revenue by region. This uses the same synthetic CRM and policy as the [TypeScript quickstart](quickstart-typescript.md).

Complete the [holder and Python installation](installation.md). Run the commands from your checkout root.

## Start the receiving holder

In a separate terminal:

```bash
cd examples/enterprise-analytics
../../target/debug/remit serve
```

It listens on `http://127.0.0.1:8444`. Keep it running while you send the request.

## Run the sender

The complete program is `examples/first_exchange.py`:

<!-- example: examples/first_exchange.py -->

Run it from the checkout root:

```bash
REMIT_IDENTITY=examples/enterprise-analytics/keys/finance-agent.json \
  .venv/bin/python examples/first_exchange.py
```

The result contains up to four region totals, rounded to the declared precision, plus labels and terms. `receipt.verify()` verifies the signed receipt; the SDK also binds the received result to the submitted request.

The source account records stay at the holder. Its policy requires aggregates over at least 20 accounts. The sender identity is a committed demo key that the example holder already knows; generate and register your own identities when moving beyond the example.

## Integrate with an application

Use `Remit` for synchronous calls. `AsyncRemit` and `AsyncHolder` provide an asyncio API. The language of the sender does not determine the language of the remote program: a Python sender can submit SQL or a JavaScript kernel, and a holder configured with the Python engine can also execute `python/monty` kernels.

See the [Python SDK](../sdk/python/README.md), [kernel guide](kernels.md) and [receipt guide](receipts.md). Stop the example holder with Ctrl-C when you finish.
