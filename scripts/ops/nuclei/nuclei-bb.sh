#!/usr/bin/env bash
# @32014SRG
# Usage: nuclei-bb.sh <url|list>
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "Usage: nuclei-bb.sh <url|list>"; exit 0
fi

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { log "$c_red" "missing target"; exit 2; }

OUTDIR="${BB_DIR:-$HOME/bounty}/vulns"
mkdir -p "$OUTDIR"

nuclei -u "$TARGET" -severity medium,high,critical -exclude-tags dos -rate-limit 150 \
  | tee "$OUTDIR/nuclei_$(date +%H%M%S).txt"

~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "Nuclei done for $TARGET" || true
exit 0
