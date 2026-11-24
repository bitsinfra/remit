# remit-types

Remit Types (RT): bounded result types, capacity in bits, validator and trusted transforms.

Remit Types (RT) are bounded result types. This crate parses and validates them, computes their capacity in bits (the most information a value of the type can carry), validates and normalizes values, and maps the JSON Schema profile to RT. See [spec/rt.md](https://github.com/bitsinfra/remit/blob/main/spec/rt.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
