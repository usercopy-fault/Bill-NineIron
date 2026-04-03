#!/usr/bin/env bash
# @32014SRG
# Usage: nuclei-js-audit.sh <list>
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

LIST="${1:-}"
[[ -z "$LIST" || ! -f "$LIST" ]] && { log "$c_red" "missing list"; exit 2; }

OUTDIR="${BB_DIR:-$HOME/bounty}/vulns"
mkdir -p "$OUTDIR"

nuclei -l "$LIST" -t ~/nuclei-templates/http/exposures/ -severity medium,high,critical \
  | tee "$OUTDIR/nuclei_js_$(date +%H%M%S).txt"

~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "JS nuclei done" || true
exit 0
