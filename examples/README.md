# Examples

All data is synthetic (`scripts/gen-example-data.py`). Keys under `*/keys/`
are demo keys committed so the examples run out of the box. Never reuse them.

| Example | Holder | What it shows |
|---|---|---|
| [personal-vault](personal-vault) | `did:web:alice.vault.example` on :8443 | Kernel mode over a calendar: a travel agent gets three free slots (~64 bits), never titles, attendees or locations. Hidden columns, purpose binding, a 128-bit cap, `no-forward` labels, latency padding. A SQLite health table that is aggregate-only with `k ≥ 7` days and first-use approval. |
| [enterprise-analytics](enterprise-analytics) | `did:web:hr-data.acme.example` on :8444 | Aggregate-only CRM (`k ≥ 20` distinct accounts, enforced in the plan), a hashed-email mask, Zod return types, a kernel that post-processes two aggregate reads, and a DP-governed copy (OpenDP noise; ε ledger; cached noisy answers). |
| [b2b-overlap](b2b-overlap) | `did:web:company-b.example` on :8445 | Clean-room overlap: Company A sends 400 hashed emails as a param; the kernel sees B's hashed list inside the sandbox; at most 14 bits leave. A tight daily bit budget bounds repeated probing. |
| [docs-rag](docs-rag) | `did:web:docs.corp.example` on :8446 | Retrieval without bulk export: `fts('kb', $q, 5)` (BM25) returns ids and scores, joined back to the policy view of the docs table; only snippets of matching docs leave. |
| [graph-demo.ts](graph-demo.ts) | personal-vault + enterprise-analytics | Sender-orchestrated multi-Holder graph (`runGraph`): one Holder's typed result parameterizes the next remit; labels and terms are merged, and provenance is kept per node. |

Run any of them:

```bash
cd examples/personal-vault && ../../target/release/remit serve
```

```bash
cd examples/personal-vault && REMIT_IDENTITY=keys/travel-agent.json node demo.ts
```

Use `enterprise-analytics` with `keys/finance-agent.json`, and `b2b-overlap` with
`keys/company-a.json`. personal-vault also enables Python (Monty) kernels:
pass `lang: "python/monty"` to `holder.kernel(...)`. CLI equivalents:

```bash
remit check remits/free-slots.example.json --holder http://127.0.0.1:8443 --identity keys/travel-agent.json
```

```bash
remit pull http://127.0.0.1:8443
```

The playground is at `http://127.0.0.1:8443/playground`. It uses an ephemeral
`did:key`, so most policies deny it, but you still see diagnostics, capacity and
the admission trace. Run `remit dev --catalog .remit/alice/catalog.json` for a
permissive emulator over synthetic data.
