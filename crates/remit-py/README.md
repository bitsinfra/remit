# remit-native

The Rust verifier core of [Remit](https://github.com/bitsinfra/remit) as a Python
extension module (`remit_native`, built with [PyO3](https://pyo3.rs) and
[maturin](https://www.maturin.rs)): JSON canonicalization (RFC 8785), `remit_id`,
Remit Type capacity and validation, and the Remit SQL profile and binder.

The [`remit`](https://pypi.org/project/remit-protocol/) SDK uses it automatically when it is
installed; without it the SDK falls back to its pure-Python implementation.

```bash
pip install remit-protocol remit-native
```

Build from a checkout with `maturin build --release -m crates/remit-py/Cargo.toml`.

## License

Apache-2.0
