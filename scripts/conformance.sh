#!/usr/bin/env bash
# Run the black-box conformance suite against the example Holders.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${REMIT_BIN:-$PWD/target/debug/remit}"
rc=0
run() {
  local dir="$1" port="$2" key="$3" log
  log="$(mktemp)"
  # A copy of the config with a fresh data dir and roomy budgets.
  sed -e "s|^data_dir = .*|data_dir = \"$(mktemp -d)\"|" -e 's/^bits_per_principal_per_day.*/bits_per_principal_per_day = 1000000/' \
    -e 's/^bits_global_per_day.*/bits_global_per_day = 10000000/' "examples/$dir/remit.toml" > "examples/$dir/.remit.conformance.toml"
  (cd "examples/$dir" && exec "$BIN" serve --config .remit.conformance.toml) > "$log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 240); do curl -sf "http://127.0.0.1:$port/healthz" > /dev/null && break; sleep 0.25; done
  echo "== $dir"
  "$BIN" conformance "http://127.0.0.1:$port" --identity "examples/$dir/keys/$key" ${4:+--program "$4"} || { rc=1; tail -5 "$log"; }
  kill "$pid" 2> /dev/null || true
  wait "$pid" 2> /dev/null || true
  rm -f "examples/$dir/.remit.conformance.toml"
}
run personal-vault 8443 travel-agent.json
run enterprise-analytics 8444 finance-agent.json
exit $rc
