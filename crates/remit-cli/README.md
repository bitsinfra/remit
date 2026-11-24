# bitsinfra-remit

The `remit` command-line tool (`cargo install bitsinfra-remit`): `serve` a Holder from `remit.toml`, `keygen`, `sign`, `check`, `explain`, `run`, `lint`, `pull` a catalog and generate types, `dev` (a local emulator over synthetic data), `conformance`, `replay`, `bench`, and policy, receipt and authority tooling.

The Holder loads its kernel engine components from disk; build them with `scripts/build-engine.sh` from the repository or take them from a release.

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
