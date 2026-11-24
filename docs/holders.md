# Run a holder for your agent

A holder is the receiving side of an exchange. It owns the catalog, data connections, access policy, execution limits and signing identity. Your agent can publish a holder without handing another agent its database credentials or a shell.

## Start from a working configuration

After [building the holder](installation.md), run the synthetic enterprise configuration:

```bash
./target/debug/remit serve --config examples/enterprise-analytics/remit.toml
```

Paths in the configuration resolve relative to `remit.toml`. You can run this command from the checkout root. The configuration’s listener is `127.0.0.1:8444`; `--listen` overrides it.

The configuration connects CSV sources, exposes selected columns, registers a sender and loads Cedar policies. Inspect [the complete example configuration](../examples/enterprise-analytics/remit.toml) before creating your own.

## Connect a data source

This excerpt exposes a CSV file as `crm.accounts`:

```toml
[[source]]
name = "crm"
kind = "csv"
path = "data/accounts.csv"
table = "accounts"
```

For Postgres, use the `postgres` source kind and keep the connection string in the holder’s environment:

```toml
[[source]]
name = "crm"
kind = "postgres"
dsn = "env:CRM_DATABASE_URL"
tables = ["accounts"]
```

Set `CRM_DATABASE_URL` in the process or service environment. It is not a sender parameter and must not appear in the public catalog. Source reads are pinned to snapshots; use the refresh settings described in [operations](operations.md) when the underlying data changes.

Other source kinds include Parquet, JSON, SQLite, Delta and Iceberg. Some connectors require optional build features. The [read-plane configuration](../crates/remit-read/src/config.rs) is the source for exact connector fields.

## Describe the resource

```toml
[catalog."crm.accounts"]
description = "Revenue by region. Aggregates only."
purposes = ["analytics"]
operations = ["aggregate"]
aggregate_only = true
k = 20
privacy_unit = "account_id"
max_bits = 4096

[catalog."crm.accounts".columns]
region = { enum = true }
name = { expose = false }
owner_email = { expose = false }
```

This is a resource excerpt, not a complete holder configuration. Keep the source, holder identity, registered principals, runtime, budgets and [policy](policies.md) from your configuration. Columns are exposed by default; explicitly hide fields the sender should not discover.

## Give the holder and sender their own identities

Generate new keys outside the committed example key files:

```bash
./target/debug/remit keygen --out holder-key.json
./target/debug/remit keygen --out sender-key.json
```

Set `holder.identity` to the holder key file. Register the sender’s public identity and keys in `[[principal]]`, assign its groups, and authorize those groups in policy. Keep private key files out of version control and distribution artifacts. A self-certifying `did:key` can authenticate without a registry when enabled, but still needs an admitting policy.

Set the runtime engine path and use process isolation for an untrusted sender. See [operations](operations.md) before serving beyond localhost and [catalog reference](../spec/catalog.md) for what peers discover.
