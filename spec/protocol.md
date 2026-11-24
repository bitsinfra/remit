# Protocol and transports

## Native HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/remit` | Catalog (signed, `ETag` = catalog hash, `If-None-Match` → 304) |
| `GET /.well-known/agent-card.json` | A2A Agent Card advertising the Remit extension and catalog URL |
| `POST /remit/v1/check` | Admission only: decision, diagnostics, counter-offers, facts, access card, coarse cost, trace |
| `POST /remit/v1/run` | Submit and execute; `Prefer: respond-async` → `202` + `Location` |
| `GET /remit/v1/runs/{id}` | Run status/result; `Accept: text/event-stream` streams `progress`/`result` events; approval tickets are queryable here too |
| `PUT /remit/v1/blobs/{sha256}` | Upload code once (body hash must match) |
| `GET /remit/v1/receipts/{id}` | Fetch a receipt envelope |
| `GET /remit/v1/log/head` | Signed tree head of the receipt transparency log (RFC 6962 Merkle root) |
| `GET /remit/v1/log/proof/{id}` | Inclusion proof for a receipt + signed tree head |
| `POST /remit.v1.RemitService/{Method}` | `spec/proto/remit/v1/remit.proto` over Connect unary (`application/json`, `application/proto`) and gRPC (`application/grpc+proto`, HTTP/2 with trailers) |
| `GET /.well-known/did.json` | `did:web` document with the Holder key |
| `GET /playground` | Browser playground (in-browser signing, access card, trace) |
| `POST /mcp` | MCP extension (below) |
| `POST /a2a` | A2A JSON-RPC (below) |
| `GET/POST /admin/approvals…` | Approver API (Bearer `holder.admin_token`) |
| `GET /metrics`, `GET /healthz` | Operations |

Envelopes are sent as `application/vnd.remit.envelope+json`; results are JSON.
With `Accept: application/vnd.apache.arrow.stream`, a successful `table<…>` result
is an Arrow IPC stream and everything else (receipt included) travels base64 in
the `Remit-Response` header. `result_sha256` always covers the JCS JSON rows.
HTTP/1.1 and HTTP/2. `GET /metrics` is JSON, or OpenMetrics text when asked for.
`POST /admin/refresh` loads a fresh pinned snapshot of every source.
Holders can export OTLP/HTTP metrics and spans (`[holder] otlp_endpoint`): one trace per
remit, a span per admission stage plus execution, no params or values.

## MCP extension `io.github.bitsinfra/remit`

Targets the stateless MCP 2026-07-28 core: `server/discover` (and `initialize`
for older clients), no session state, routable by `Mcp-Method`/`Mcp-Name`.

- Resource `remit://catalog` (`resources/list`, `resources/read`).
- Tools `remit_check` and `remit_run`, argument `{envelope}`; results in
  `structuredContent` (and a text copy).
- **Counter-offers** are Multi Round-Trip Requests:
  `{"resultType": "input_required", "inputRequests": {"counter_offer": {"json_patch": […]}}}`;
  the client retries `remit_run` with a re-signed, patched envelope.
- **Pending approvals** use `io.modelcontextprotocol/tasks`:
  `{"resultType": "task", "task": {"taskId": "<ticket>", "status": "input_required"}}`
  and `tasks/get`.
- **Sender helper `remit-mcp`** (stdio, `sdk/ts/bin/remit-mcp.ts`) exposes
  `remit_describe(holder)`, `remit_check(holder, program)`,
  `remit_send(holder, program)`; it fetches/verifies catalogs, runs local checks,
  signs and returns repair diagnostics, so the LLM only writes SQL or TS. Results
  are prefixed as untrusted data.

## A2A v1.0 extension

- **Method extension**: `remit/check`, `remit/run` with `params.envelope`.
- **Profile**: in `message/send`, a `DataPart` with media type
  `application/vnd.remit.envelope+json` carries the envelope; the response task's
  artifact is a `DataPart` (`application/vnd.remit.result+json`) holding the
  result, labels, terms and receipt.
- The Agent Card's `capabilities.extensions[]` entry, whose `uri` is this section
  (`https://github.com/bitsinfra/remit/blob/main/spec/protocol.md#a2a-v10-extension`),
  carries `params.catalog`.

## Identity

- Senders: `did:key` (self-certifying; Holders may disable with
  `allow_did_key = false`) or registered ids (`did:web`, WIMSE/SPIFFE URIs) with
  their `did:key` public keys in `[[principal]]`.
- Delegated authority: Biscuit tokens in `authority[]`, verified against
  `[authority] roots`. Datalog facts available to token checks: `principal`,
  `purpose`, `mode`, `result_bits`, `fuel`, `epsilon_milli`, `aggregate_only`,
  `time`, `resource`, `column(resource, name)`; rights are
  `right(resource | "*", action)` (a `read` right covers `aggregate`).
  Attenuation blocks can only add checks.
- Holder: catalog and receipts are signed with the Holder key (Ed25519, or P-256
  for HSM/KMS keys); `keys[0]` in the catalog.

### Sender key resolution

| Sender id | Key |
|---|---|
| `did:key:z…` | self-certifying (Ed25519, P-256) |
| registered id | `[[principal]] keys` |
| `did:web:host[:path]` | DID document, only for hosts in `[[identity.web]]` |
| `https://agent` (Web Bot Auth) | `/.well-known/http-message-signatures-directory` of an allowlisted host; the key id fragment is the RFC 7638 thumbprint |
| `spiffe://…`, `wimse://…` | `cnf.jwk` of a Workload Identity Token from a configured issuer, with a Workload Proof Token bound to the request |

Holders dereference only hosts they allowlisted: HTTPS, no redirects, 64 KiB,
3 s, cached.

### Transport signatures (RFC 9421)

Requests may carry `Signature-Input` / `Signature` covering `@method`,
`@authority`, `@path`, `@query` (when present) and `content-digest` (RFC 9530),
with `created`, `nonce` and `tag="remit"`. A present signature must verify and be
made by the envelope's sender. `[identity] require_transport_signature = true`
makes it mandatory. The SDKs sign every request.
