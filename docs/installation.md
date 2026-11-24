# Installation

The research-preview walkthroughs use a Remit source checkout and synthetic example data. Run the commands below from that checkout’s root. You do not need credentials for a real database or an LLM provider.

## Build the holder and CLI

Install Rust **1.98 or newer** through rustup. The checkout’s `rust-toolchain.toml` selects stable Rust and the Wasm targets. Building the holder also requires `protoc`, the Protocol Buffers compiler.

```bash
rustup target add wasm32-wasip2 wasm32-unknown-unknown
scripts/build-engine.sh js
cargo build --locked -p bitsinfra-remit
```

The executable is `target/debug/remit`. The JavaScript kernel engine is `engines/js/dist/remit_engine_js.wasm`. Keep the engine at the path named by the holder’s configuration, even when the first request is a SQL query.

Check the executable:

```bash
./target/debug/remit --version
./target/debug/remit serve --help
```

For an optimized build, add `--release` to the Cargo command and use `target/release/remit` in the following guides. To enable Python kernels, also run `scripts/build-engine.sh python` and set `runtime.python_engine` in the holder configuration. Sending a query from Python does not require the Python kernel engine.

## TypeScript sender

Use Node.js **22.18 or newer** to run the source examples. Install the SDK’s dependencies:

```bash
npm ci --prefix sdk/ts
```

Build the native verifier for full offline SQL checks:

```bash
cargo install wasm-bindgen-cli --version 0.2.122 --locked
scripts/build-verifier.sh
```

The holder remains responsible for admission, regardless of the sender’s local checks. The [first TypeScript exchange](quickstart-typescript.md) runs the SDK source from this checkout.

## Python sender

Use Python **3.10 or newer**. Install the local SDK into a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./sdk/python
```

The base Python SDK has no required third-party dependencies. Continue with the [Python quickstart](quickstart-python.md).

## Go sender

Use Go **1.23 or newer**. The SDK lives in `sdk/go` and uses the standard library. A source consumer can add a local module replacement while developing against the checkout:

```bash
go mod edit -replace github.com/bitsinfra/remit/sdk/go=/absolute/path/to/remit/sdk/go
go mod tidy
```

Run this in your application’s existing Go module after adding the import shown in the [Go SDK reference](../sdk/go/README.md). Replace the path with your checkout’s actual location.

## Package names

Release packages use `bitsinfra-remit` for the Rust CLI, `remit-protocol` for the TypeScript SDK and `remit` for Python. The SDK references show their package installation commands. Use the checkout instructions above for this research-preview walkthrough; they do not depend on package publication.
