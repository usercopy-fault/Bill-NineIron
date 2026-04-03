#!/usr/bin/env bash
# @32014SRG
# Usage: bb-report-gen.sh <target>
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "Usage: bb-report-gen.sh <target>"; exit 0
fi

TARGET="${1:-${BB_TARGET:-}}"
[[ -z "$TARGET" ]] && { log "$c_red" "missing target"; exit 2; }

BASE="$HOME/bounty/$TARGET"
OUT="$BASE/reports/report.md"
mkdir -p "$BASE/reports"

cat > "$OUT" <<DOC
# Bug Bounty Report — $TARGET

## Summary
- Date: $(date)
- Scope: 

## Findings
### Finding 1
- Severity: 
- Endpoint: 
- Steps:
  1. 
  2. 
- Expected vs Actual:
- Impact:
- Remediation:

## Evidence
- Requests/Responses:
- Screenshots:
- Timestamps:
DOC

log "$c_green" "Report created at $OUT"
~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "Report skeleton created for $TARGET" || true
exit 0
