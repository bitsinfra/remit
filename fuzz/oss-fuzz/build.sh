#!/bin/bash -eu
cd "$SRC/remit"
cargo fuzz build -O
for f in fuzz/fuzz_targets/*.rs; do
  n="$(basename "${f%.rs}")"
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$n" "$OUT/"
done
