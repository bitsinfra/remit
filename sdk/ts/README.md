# remit-protocol

The TypeScript Sender SDK for [Remit](https://github.com/bitsinfra/remit): agents
exchange programs, not messages. Write SQL queries or JS/TS kernels against a
Holder's typed catalog, check them locally with the same verifier the Holder runs,
sign and submit them, and get back typed results with verified receipts.

```bash
npm install remit-protocol
```

Node.js ≥ 20 (ESM). A WebCrypto build for browsers and workers is exported as
`remit-protocol/browser`.

Browser applications must provide the Wasm verifier and serve the Holder through
the same origin, for example with a reverse proxy. The stock Holder does not
enable cross-origin requests. Preserve the `Remit-Signature` response header so
the browser can verify the catalog.

## Query mode

```ts
import { Remit } from "remit-protocol";
import { z } from "zod";

const remit = new Remit({ identity: await Remit.identity.fromEnv() }); // REMIT_IDENTITY=keys/agent.json
const crm = await remit.holder("https://crm.example.com");             // fetches and verifies the signed catalog

const arr = await crm.query({
  sql: `SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region`,
  returns: z.array(z.object({
    region: z.enum(crm.enums("crm.accounts.region")),
    arr: z.number().min(0).max(1e10).multipleOf(1000),
  })).max(20),
});

arr.value;   // typed values; strings come back as Untrusted
arr.receipt; // verified receipt: labels, terms, data versions, result hash
```

Return types can be Remit Types built with `t`, Zod schemas, any Standard Schema,
or JSON Schema. Every type must be bounded; the SDK computes its capacity in bits
before anything is sent.

## Kernel mode

```ts
import { Remit, t } from "remit-protocol";

const vault = await remit.holder("http://127.0.0.1:8443");
const slots = await vault.kernel<{ start: Date; end: Date }[]>({
  reads: {
    busy: vault.sql`SELECT start_at, end_at FROM calendar.events
                    WHERE start_at < ${t.param("until")} AND end_at > ${t.param("from")}`.maxRows(500),
  },
  params: { from: new Date("2026-11-24T00:00:00Z"), until: new Date("2026-12-08T00:00:00Z") },
  returns: t.list(t.struct({ start: t.timestamp({ granularity: "15m" }), end: t.timestamp({ granularity: "15m" }) }), { max: 3 }),
  limits: { wall: "250ms", memory: "16MiB", fuel: 50_000_000, output: "1KiB" },
  source: `export default function main({ busy }, p) { /* … */ }`,
  purpose: "scheduling",
});
```

Kernels are type-checked against their reads, params and result type, and their
fuel is estimated from the catalog, before submission.

## Errors and repair

A rejected remit throws `RemitError` with structured diagnostics (stable `code`,
JSON-pointer `path`, source `span`, `hint`, and often a JSON Patch `fix`), and
counter-offers when the Holder would admit a narrower request.

## More

- `runGraph` orchestrates multi-Holder graphs where one typed result parameterizes
  the next remit.
- `EmbeddedHolder` serves in-process data as Remit resources through a supervised
  `remit serve` sidecar.
- `remit-mcp` is a stdio MCP server exposing `remit_describe`, `remit_check` and
  `remit_send` to any MCP client; `remit-ts` pulls catalogs, generates types and
  builds, checks and runs kernels from the command line.
- `skill/SKILL.md` is an authoring guide for agents that write remits.

See the [specification](https://github.com/bitsinfra/remit/tree/main/spec) for the
protocol.

## License

Apache-2.0

