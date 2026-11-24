# remit-kernel

Remit compute plane: Wasmtime host for kernel engines (pooling, fuel, deterministic WASI stubs, worker processes).

The compute plane: a Wasmtime host for `remit:kernel` engine components with a pre-initialized instance pool, fuel-only deterministic metering with priced host I/O, deterministic WASI stubs, sandboxed per-trust-domain worker processes (macOS sandbox; Linux namespaces, Landlock and seccomp), microVM isolation, and Sender-built components compiled on a restricted engine. See [spec/kernel.md](https://github.com/bitsinfra/remit/blob/main/spec/kernel.md) and [spec/isolation.md](https://github.com/bitsinfra/remit/blob/main/spec/isolation.md).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
