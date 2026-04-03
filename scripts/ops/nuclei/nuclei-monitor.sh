#!/usr/bin/env bash
# @32014SRG
# Usage: nuclei-monitor.sh
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

trap 'log "$c_red" "interrupted"; exit 3' INT

SCOPE="${BB_SCOPE_FILE:-$HOME/.bb_scope}"
if [[ ! -f "$SCOPE" ]]; then
  log "$c_red" "scope file not found: $SCOPE"; exit 2
fi

log "$c_amber" "monitoring $SCOPE"
while true; do
  nuclei -l "$SCOPE" -severity medium,high,critical -exclude-tags dos -rate-limit 100 \
    | tee -a "$HOME/bounty/nuclei_monitor.log" || true
  ~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "Nuclei monitor run complete" || true
  sleep 600
done
