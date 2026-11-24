# remit-receipt

Remit receipts: DSSE-signed run records, label meet, hash-chained append-only log.

Receipts for every terminal state: DSSE-signed run records, label and terms meet, a hash-chained append-only log, RFC 6962 Merkle tree heads with inclusion proofs, and TEE attestation evidence. See [spec/receipts.md](https://github.com/bitsinfra/remit/blob/main/spec/receipts.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
