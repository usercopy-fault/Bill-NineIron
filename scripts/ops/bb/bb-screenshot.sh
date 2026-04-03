#!/usr/bin/env bash
# @32014SRG
# Usage: bb-screenshot.sh <live_hosts_file>
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

trap 'log "$c_red" "interrupted"; exit 3' INT

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "Usage: bb-screenshot.sh <live_hosts_file>"; exit 0
fi

LIST="${1:-}"
[[ -z "$LIST" || ! -f "$LIST" ]] && { log "$c_red" "missing live hosts file"; exit 2; }

OUTDIR="${BB_DIR:-$HOME/bounty}/recon/screenshots"
mkdir -p "$OUTDIR"

log "$c_amber" "Capturing screenshots"
if command -v gowitness >/dev/null 2>&1; then
  gowitness file -f "$LIST" --screenshot-path "$OUTDIR" || true
elif command -v aquatone >/dev/null 2>&1; then
  aquatone -silent -list "$LIST" -out "$OUTDIR" || true
else
  log "$c_red" "gowitness/aquatone not found"; exit 2
fi

log "$c_green" "Screenshots saved to $OUTDIR"
~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "Screenshots complete" || true
exit 0
