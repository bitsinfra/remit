#!/usr/bin/env bash
# Compile the verifier to Wasm for the TS SDK (sdk/ts/wasm/).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
rustup target add wasm32-unknown-unknown >/dev/null
# Keep local paths (checkout, cargo registry) out of the published Wasm.
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/remit --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
  PATH="$(dirname "$(rustup which cargo)"):$PATH" cargo build --profile wasm -p remit-verify-wasm --target wasm32-unknown-unknown
wasm-bindgen --target nodejs --out-dir sdk/ts/wasm target/wasm32-unknown-unknown/wasm/remit_verify_wasm.wasm
# The SDK package is ESM; the Node binding is CommonJS.
echo '{"type":"commonjs"}' > sdk/ts/wasm/package.json
# Browsers and workers.
wasm-bindgen --target web --out-dir sdk/ts/wasm/web target/wasm32-unknown-unknown/wasm/remit_verify_wasm.wasm
echo '{"type":"module"}' > sdk/ts/wasm/web/package.json
echo "verifier → sdk/ts/wasm/"
