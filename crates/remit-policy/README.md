# remit-policy

Remit policy: Cedar over analyzer facts, presets, Biscuit authority, budget ledgers.

Cedar over analyzer facts: the Remit Cedar schema and engine, policy presets, lint and diff (with SMT-backed checks when `z3` is available), Biscuit authority tokens, and the write-ahead-logged bit, ε and fuel budget ledgers. See [spec/admission.md](https://github.com/bitsinfra/remit/blob/main/spec/admission.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
