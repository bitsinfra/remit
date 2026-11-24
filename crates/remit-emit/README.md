# remit-emit

Remit emit plane: result validation, trusted transforms (quantize, clamp, DP noise via OpenDP), encoding.

The emit plane: validates kernel and query output against the declared Remit Type, applies trusted transforms (quantize, clamp), adds differential-privacy noise via OpenDP, decodes kernel CBOR output, and shapes results for encoding (JSON, or Arrow IPC for `table` types).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
