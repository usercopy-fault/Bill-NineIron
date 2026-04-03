#!/usr/bin/env bash
# @32014SRG
# Usage: bb-test-watch.sh
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

if [[ -f Cargo.toml ]]; then
  log "$c_amber" "cargo test"
  cargo test
elif [[ -f go.mod ]]; then
  log "$c_amber" "go test ./..."
  go test ./...
elif [[ -f pyproject.toml || -f setup.py ]]; then
  log "$c_amber" "pytest -v"
  pytest -v
else
  log "$c_red" "no test config detected"; exit 1
fi
