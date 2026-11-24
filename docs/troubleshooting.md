# Diagnose an exchange

Distinguish failure to connect, a request that was not admitted, and an admitted run that failed. They require different repairs.

## The local example does not start

| Symptom | Check |
| --- | --- |
| Missing engine component | Run `scripts/build-engine.sh js` from the checkout root; check `runtime.engine` relative to `remit.toml`. |
| Port 8444 is in use | Stop your previous example holder, or choose another listener with `--listen` and set the sender’s `HOLDER` URL to match. |
| `protoc` is missing during compilation | Install the Protocol Buffers compiler and make it available on PATH. |
| Sender cannot find its identity | Run from the checkout root and set `REMIT_IDENTITY` to the example key path shown in the quickstart. |
| Python cannot import `remit` | Use the virtual environment where you installed `./sdk/python`. |

Do not stop an unrelated service to free a port. Both quickstart programs accept `HOLDER` to choose a different local endpoint.

## Inspect a rejection

TypeScript throws `RemitError` with a decision, diagnostics and any counter-offer. Python exposes the same structured error model; Go uses `*remit.Error`.

```ts
import { RemitError } from "remit-protocol";

try {
  // Submit your query or kernel here.
} catch (error) {
  if (!(error instanceof RemitError)) throw error;
  for (const diagnostic of error.diagnostics) {
    console.error(diagnostic.code, diagnostic.path, diagnostic.message);
  }
}
```

Use a diagnostic’s `code` for programmatic handling. Its `path` and optional source `span` locate the problem. A `hint` or JSON Patch `fix` may suggest a repair, but the application still owns the decision to change and re-sign a request.

## Common repairs

| Problem | Repair |
| --- | --- |
| Unbounded result type | Add finite ranges, string lengths, list lengths and timestamp bounds. |
| Hidden or missing column | Refresh the signed catalog and use its visible columns; do not probe alternate names to bypass policy. |
| Raw rows denied | Request an aggregate if that is what the resource permits. |
| `now()` or positional SQL parameters | Use declared named inputs such as `$from`. |
| Wrong purpose or identity | Use a purpose offered by the resource and an identity the holder authorizes. |
| Budget exhausted | Reduce the answer’s capacity or wait for the applicable window; obtain a policy change from the holder owner when needed. |
| Counter-offer | Inspect the proposed limits and re-sign only if the application accepts them. |
| Pending approval | Complete the holder’s approval flow and follow the ticket; do not treat HTTP 202 as a completed answer. |

`remit explain` shows the admission trace without running the program. The [diagnostic reference](../spec/diagnostics.md) lists stable codes.

## Interpret a run status

`ok` means a typed result was released. `limit_exceeded` means a runtime cap was hit. `type_violation` means the output did not fit `returns`. `denied` means policy, authority, budget or a runtime read refused the work. `internal` covers kernel or engine failure.

A network timeout leaves the outcome uncertain. Use the returned run location or run ID when available instead of assuming the holder did no work. The [HTTP protocol](../spec/protocol.md) defines async submission and status retrieval.

If catalog or receipt verification fails, check the expected holder identity, proxy headers and configured keys. Do not disable verification to turn an unverified response into an answer.
