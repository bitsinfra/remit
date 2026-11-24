# CLI reference

The `remit` executable runs a holder and provides sender, policy and receipt tools. In a source checkout, use `./target/debug/remit`; an optimized build is at `./target/release/remit`.

## Holder and identities

| Command | Purpose |
| --- | --- |
| `remit serve --config remit.toml` | Run a holder. `--listen` overrides its configured address. |
| `remit keygen --out identity.json` | Generate an identity file. `--id` selects a registered ID; `--p256` selects P-256. |
| `remit pull HOLDER --name NAME` | Fetch the signed catalog and generate local types, SQL schema and examples under `.remit/`. |
| `remit dev --catalog CATALOG` | Run a local emulator over synthetic data. |

The emulator is for authoring and repair. Passing it does not establish that a real holder will admit the request.

## Author and execute

| Command | Purpose |
| --- | --- |
| `remit lint MANIFEST` | Verify a manifest offline without data. |
| `remit sign MANIFEST --identity KEY --holder-id ID --out ENVELOPE` | Fill defaults and sign an envelope. |
| `remit check FILE --holder URL --identity KEY` | Ask for admission without execution. |
| `remit explain FILE --holder URL --identity KEY` | Show the access card, capacity and admission trace. |
| `remit run FILE --holder URL --identity KEY` | Submit and execute. |

`FILE` can be an unsigned manifest that the CLI signs with the supplied identity, or a signed envelope. `REMIT_IDENTITY` can supply the identity path. `--accept-counter-offers` explicitly permits the CLI to apply a proposed narrowing and re-sign; omit it when an application or person needs to review the proposed change.

For a complete local command, follow the [first exchange](quickstart-typescript.md#inspect-the-same-exchange-from-the-cli).

## Policy and receipts

| Command | Purpose |
| --- | --- |
| `remit policy lint --config CONFIG` | Validate policy and analyze its rules. |
| `remit policy diff BEFORE AFTER --config CONFIG` | Show changed decisions between policy files. |
| `remit policy promote DRAFT DEST --approved-by NAME --config CONFIG` | Promote an approved draft after analysis. |
| `remit receipts verify FILE --holder-key KEY` | Verify a receipt or receipt log. |
| `remit replay --config CONFIG --envelope FILE --receipt FILE` | Replay recorded work on the holder side. |
| `remit authority keygen` | Generate a Biscuit authority key pair. |
| `remit authority issue` / `remit authority attenuate` | Issue authority or narrow an existing token. |

Use `remit COMMAND --help` or `remit COMMAND SUBCOMMAND --help` for exact flags. Authority tokens and private keys are credentials, not debugging output to share publicly.

## Conformance and measurements

`remit conformance --holder URL --identity KEY` exercises a holder against the protocol. `remit bench` measures the local implementation and engine. Performance depends on the machine, engine, data and isolation profile; the docs do not promise a latency from the CLI’s default workload.

The TypeScript package also includes `remit-ts` for authoring kernels and `remit-mcp` for a sender-side MCP server. See [agent runtime integration](integrations.md).
