# remit-verify-wasm

The Holder's verifier compiled to Wasm for SDKs (canonicalization, remit_id, RT capacity/validation, Remit SQL profile).

The Holder's verifier compiled to WebAssembly for SDKs: canonicalization, `remit_id`, Remit Type capacity and validation, and the Remit SQL profile, exposed through `wasm-bindgen`. The TypeScript SDK ships its build output.

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
