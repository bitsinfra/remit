# remit-sql

Remit SQL: a strict, deterministic dialect profile over sqlparser-rs.

The Remit SQL dialect profile over [sqlparser-rs](https://crates.io/crates/sqlparser): a strict, deterministic subset (SELECT only, named params, no clocks or randomness) plus an offline binder that resolves names against a catalog. See [spec/sql.md](https://github.com/bitsinfra/remit/blob/main/spec/sql.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
