# remit-wire

Remit wire format: manifest, JCS (RFC 8785) canonicalization, DSSE envelopes, identities.

The remit manifest, RFC 8785 JSON canonicalization (JCS), `remit_id`, DSSE envelopes (Ed25519, P-256), `did:key` identities, RFC 9421 HTTP message signatures, and compact JWS verification for WIMSE workload identity and OAuth transaction tokens. The `crypto` feature (default) enables signing and verification; without it the crate is suitable for Wasm verifiers. See [spec/manifest.md](https://github.com/bitsinfra/remit/blob/main/spec/manifest.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
