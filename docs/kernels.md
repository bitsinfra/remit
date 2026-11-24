# Send a kernel

Use a kernel when a query alone cannot express the answer. The sender declares every read template, supplies a small program, and bounds the result. The receiving holder checks both the reads and the program before execution.

## A program over declared reads

The enterprise example computes win rate from two aggregate reads: won deals and all closed deals. Its kernel is:

```js
export default function main({ won, all }, p) {
  const wins = new Map(won(p).rows().map(r => [r.segment, r.n]));
  return all(p).rows()
    .map(r => ({
      segment: r.segment,
      win_rate: (wins.get(r.segment) ?? 0) / r.n,
    }))
    .sort((a, b) => b.win_rate - a.win_rate);
}
```

`won` and `all` are declared SQL templates, not arbitrary database connections. Their queries join deals to accounts, group by segment, and carry the holder’s aggregate policy. The result is at most three segments, each with a rate between zero and one at 0.01 precision.

The complete program, reads, parameters, limits and result type live in [win-rate-kernel.json](../examples/enterprise-analytics/remits/win-rate-kernel.json).

With the enterprise holder from the quickstart running, execute it from the checkout root:

```bash
./target/debug/remit run \
  examples/enterprise-analytics/remits/win-rate-kernel.json \
  --holder http://127.0.0.1:8444 \
  --identity examples/enterprise-analytics/keys/finance-agent.json
```

## Submit from the SDK

`holder.kernel()` takes `reads`, `params`, `source`, `returns`, `limits` and `purpose`. Each read declares SQL, parameter types, a row cap and, when needed, a call cap. The SDK type-checks TypeScript kernels against the declared inputs and output before submission.

Kernel code runs inside the holder’s sandbox. It can call its declared reads; it cannot fetch a URL, import an arbitrary package or open a file on the holder. Supply changing inputs through parameters. The runtime binds the execution’s clock and randomness for replay.

## Select the language

The reference holder uses a JavaScript engine component for JavaScript and compiled TypeScript. Python kernels use `lang: "python/monty"` and require the holder to configure its Python engine. This is a restricted Python runtime, not a remote machine with arbitrary Python packages installed.

The sender’s SDK language is independent of the kernel’s language. A Python application can send JavaScript; a TypeScript application can send a Python kernel when the holder supports it.

## Bound the work

Fuel, memory, wall time, output bytes, read rows and read calls are separate limits. Exceeding a limit yields `limit_exceeded`. A kernel exception yields `internal`; the holder keeps the exception details in its logs rather than returning arbitrary error text.

See the [kernel contract](../spec/kernel.md), [isolation model](../spec/isolation.md) and [result types](result-types.md) for exact behavior.
