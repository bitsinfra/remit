#!/usr/bin/env bash
# Check every lemma in formal/ (each must be unsat).
set -euo pipefail
cd "$(dirname "$0")/../formal"
rc=0
for f in *.smt2; do
  r="$(z3 -T:60 "$f")"
  if [ "$r" = unsat ]; then echo "proved  $f"; else echo "FAILED  $f: $r"; rc=1; fi
done
exit $rc
