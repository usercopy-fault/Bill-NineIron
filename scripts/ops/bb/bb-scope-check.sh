#!/usr/bin/env bash
# @32014SRG
# Usage: bb-scope-check.sh <domain>
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "Usage: bb-scope-check.sh <domain>"; exit 0
fi

DOMAIN="${1:-}"
[[ -z "$DOMAIN" ]] && { log "$c_red" "missing domain"; exit 2; }

SCOPE_FILE="${BB_SCOPE_FILE:-$HOME/.bb_scope}"
if [[ ! -f "$SCOPE_FILE" ]]; then
  log "$c_red" "scope file not found: $SCOPE_FILE"; exit 2
fi

if rg -i -x "$DOMAIN" "$SCOPE_FILE" >/dev/null 2>&1; then
  log "$c_green" "IN SCOPE: $DOMAIN"; exit 0
fi

log "$c_red" "OUT OF SCOPE: $DOMAIN"
exit 1
