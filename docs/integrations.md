# Connect an agent runtime

Use the SDK directly when your application writes and coordinates programs. Use the MCP sender helper when an existing tool-calling agent should discover a holder, check a program and send it. Use the A2A binding when peers already communicate through A2A.

## MCP sender helper

The `remit-mcp` command is part of the TypeScript SDK. Its stdio server exposes:

| Tool | Use it to |
| --- | --- |
| `remit_describe` | Fetch and verify a holder’s catalog and inspect available resources. |
| `remit_check` | Check a proposed program locally and ask the holder for an admission decision. |
| `remit_send` | Sign and submit a program, then verify its result and receipt. |

From an installed SDK, configure your MCP client to start `remit-mcp` with `REMIT_IDENTITY` pointing to the sender’s private identity file. From a source checkout after the TypeScript installation steps, the equivalent command is:

```bash
REMIT_IDENTITY=examples/enterprise-analytics/keys/finance-agent.json \
  node sdk/ts/bin/remit-mcp.ts
```

The process communicates over stdio and waits for the MCP client. Keep diagnostics on stderr. Use the demo identity only with synthetic example holders; for your own data, register a dedicated sender identity and its permissions.

An agent first calls `remit_describe` with the holder URL. It then writes a program using that catalog, checks it, and sends it. Returned content is marked as untrusted data. The helper is not permission to expose all of a holder’s resources to every client using it.

## Holder-side MCP endpoint

The holder also serves `/mcp`. This is a different interface: it accepts already-signed envelopes through `remit_check` and `remit_run`. It also exposes the signed catalog as `remit://catalog`.

Use the sender helper when the agent should write SQL or TypeScript and let the helper handle signing. Use the holder endpoint when your client already constructs and signs envelopes.

## A2A binding

The holder publishes an Agent Card at `/.well-known/agent-card.json`. The card advertises the Remit extension and catalog URL. The `/a2a` endpoint accepts the `remit/check` and `remit/run` methods. The A2A message profile carries the signed envelope in a data part and returns the result and receipt as an artifact.

This binding carries the same program and policy checks as the native API. It does not ask the receiving agent’s model to follow a natural-language instruction.

## Other applications and transports

The native HTTP API and Connect/gRPC service use the same protocol. A holder can also expose a program’s read-only data sources without a peer model. The SDK’s `EmbeddedHolder` uses a supervised holder sidecar for in-process providers.

Browser clients need the Wasm verifier and a same-origin holder route or reverse proxy. The stock holder does not enable cross-origin requests. Preserve the `Remit-Signature` response header so clients can verify the catalog.

The [transport specification](../spec/protocol.md) gives exact endpoints, envelope media types and authentication behavior.
