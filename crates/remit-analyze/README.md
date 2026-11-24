# remit-analyze

Remit analyzer: derives policy facts (columns, ops, aggregate-only, k, bits, cost) and LLM-actionable diagnostics.

Derives the facts that policy decides on (columns, operations, aggregate-only, k, result bits, cost) from a remit and the Holder's catalog, and produces stable, LLM-actionable diagnostics with spans, hints and JSON Patch fixes. Includes JS/TS early-error checking for kernels.

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
