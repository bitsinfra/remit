#!/usr/bin/env bash
# Build the release artifacts twice from clean, differently-named directories
# and fail unless every byte matches. Usage: reproducible-build.sh <target> <out>
set -euo pipefail
target="$1"; out="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2> /dev/null || echo 1764000000)}"
export CARGO_INCREMENTAL=0
hash() { if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
build() {
  local dir="$1"
  rm -rf "$dir" && mkdir -p "$dir/src"
  rsync -a --exclude target --exclude node_modules --exclude .git "$root/" "$dir/src/"
  export CARGO_TARGET_DIR="$dir/target"
  export RUSTFLAGS="--remap-path-prefix=$dir/src=/remit --remap-path-prefix=$dir=/build --remap-path-prefix=$HOME/.cargo=/cargo -Cstrip=symbols"
  local native_flags="$RUSTFLAGS"
  case "$target" in *-apple-darwin) native_flags+=" -C link-arg=-Wl,-S" ;; esac
  (cd "$dir/src" && RUSTFLAGS="$native_flags" cargo build --release --locked -p bitsinfra-remit --target "$target")
  for e in js python; do
    (cd "$dir/src/engines/$e" && CARGO_TARGET_DIR="$dir/target-$e" cargo build --release --locked --target wasm32-wasip2)
  done
  mkdir -p "$dir/out"
  cp "$dir/target/$target/release/remit" "$dir"/target-js/wasm32-wasip2/release/remit_engine_js.wasm "$dir"/target-python/wasm32-wasip2/release/remit_engine_python.wasm "$dir/out/"
  rm -rf "$dir/target" "$dir/target-js" "$dir/target-python"
}
scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/source"
rsync -a --exclude target --exclude node_modules --exclude .git "$root/" "$scratch/source/"
root="$scratch/source"
a="$scratch/a"; b="$scratch/longer-name-b"
build "$a"; build "$b"
for f in "$a"/out/*; do
  n="$(basename "$f")"
  [ "$(hash "$f")" = "$(hash "$b/out/$n")" ] || { echo "NOT REPRODUCIBLE: $n" >&2; exit 1; }
  echo "reproducible: $n $(hash "$f")"
done
mkdir -p "$out" && cp "$a"/out/* "$out/"
