# Operate a holder

Run the holder as the owner of its data and policy. Keep credentials, signing keys and state separate from the public documentation and sender applications.

## Listen and terminate TLS

The examples listen on loopback. When exposing a holder to peers, put it behind an HTTPS endpoint and preserve the headers used for catalog and transport signatures. Configure the holder’s public identity to match the identity peers expect.

Sender SDKs can pin the expected catalog signing key. For example, TypeScript accepts `holder(url, { pin: expectedDidKey })`. Obtain that key through your trusted configuration rather than trusting an unexpected key returned by an endpoint.

## Preserve state

`holder.data_dir` contains durable holder state, including budget accounting and receipts. Keep it on persistent storage with permissions appropriate for the holder process. Treat a restore as restoring accounting and provenance together, not merely starting with an empty budget ledger.

Back up the configuration and its referenced policies, identity material, state directory and source snapshots as appropriate to your deployment. Protect private identities separately from public catalogs and signed receipts.

## Refresh source data

Sources load as pinned snapshots. A source can set `refresh_s` to request periodic reloads; each load creates a new pinned snapshot. An authenticated `POST /admin/refresh` triggers a refresh. Configure `holder.admin_token` through an environment variable and restrict administrative routes to authorized operators.

Changed data versions affect cached results and replay. Retain the versions required by your audit policy rather than assuming a current database can reproduce a past answer.

## Observe the holder

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Check service health. |
| `GET /metrics` | Read JSON metrics, or OpenMetrics with the corresponding Accept header. |
| `GET /remit/v1/log/head` | Obtain a signed receipt-log tree head. |
| `GET /remit/v1/log/proof/{run_id}` | Obtain an inclusion proof for a run. |

Set `holder.otlp_endpoint` for OTLP/HTTP telemetry. The reference holder exports admission and execution observations without including parameters or result values. Keep the holder’s own logs restricted: kernel error details remain there.

## Capacity and isolation

Set runtime limits and bounded queues for the workload you accept. A busy holder responds with HTTP 429 and `Retry-After`. Keep that response distinct from a policy denial; adding retries does not grant permission or budget.

Use the process isolation profile for untrusted senders and pin engine hashes when deploying engine components. The in-process and microVM profiles have different deployment requirements. Read [isolation](../spec/isolation.md) before selecting one.

The Cloudflare backend has a separate [edge profile](../backends/cloudflare/README.md) with different policy and metering behavior. Its compatibility is explicit in the receipt; it is not interchangeable with every reference-holder policy.

## Release status

This is a research preview with specification 0.1 and wire version 0.1. Consult [security reporting](../SECURITY.md), the [threat model](../spec/threat-model.md) and [versioning](../spec/VERSIONING.md) before planning a sensitive-data deployment.
