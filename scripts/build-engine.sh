#!/usr/bin/env bash
# Build the Holder-trusted engine components (JS: Boa, Python: Monty) and print
# their pinned hashes. Usage: scripts/build-engine.sh [js|python|all]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WHICH="${1:-all}"
if command -v rustup >/dev/null; then rustup target add wasm32-wasip2 >/dev/null; fi
TC="$(rustup which cargo 2>/dev/null || command -v cargo)"
export PATH="$(dirname "$TC"):$PATH"
# Keep local paths (checkout, cargo registry) out of the components so builds
# are byte-identical across machines.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/remit --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
build() {
  local dir="$1" name="$2"
  (cd "$ROOT/engines/$dir" && "$TC" build --release --target wasm32-wasip2 && mkdir -p dist &&
    cp "target/wasm32-wasip2/release/$name.wasm" dist/)
  if command -v sha256sum >/dev/null; then sha256sum "$ROOT/engines/$dir/dist/$name.wasm"; else shasum -a 256 "$ROOT/engines/$dir/dist/$name.wasm"; fi
}
case "$WHICH" in
  js) build js remit_engine_js ;;
  python) build python remit_engine_python ;;
  all) build js remit_engine_js; build python remit_engine_python ;;
  *) echo "usage: $0 [js|python|all]" >&2; exit 2 ;;
esac
echo "pin the JS hash as [runtime] engine_sha256 in remit.toml; set [runtime] python_engine to enable Python kernels"
