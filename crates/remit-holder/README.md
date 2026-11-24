# remit-holder

Remit Holder: admission pipeline, HTTP API, MCP and A2A bindings.

The Holder: the admission pipeline (authentication, replay, plan cache, analysis, Biscuit, Cedar, budgets), the native HTTP API, Connect / gRPC (`remit.v1`), MCP and A2A bindings, approvals, the signed catalog, statistics profiles and OTLP telemetry. Embed it to serve your own `TableProvider`s and functions, or run it with the `remit` CLI. See [spec/protocol.md](https://github.com/bitsinfra/remit/blob/main/spec/protocol.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
