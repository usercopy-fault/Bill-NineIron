#!/usr/bin/env bash
# @32014SRG
# Usage: bb-ng-recon.sh <target>
set -euo pipefail

c_amber='\033[38;2;232;168;32m'
c_green='\033[38;2;78;203;113m'
c_red='\033[38;2;217;95;59m'
c_dim='\033[38;2;74;64;53m'
c_reset='\033[0m'

ts() { date +%H:%M:%S; }
log() { printf '[%s] %b%s%b\n' "$(ts)" "$1" "$2" "$c_reset"; }

die() { log "$c_red" "$1"; exit 2; }

trap 'log "$c_red" "interrupted"; exit 3' INT

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "Usage: bb-ng-recon.sh <target>"; exit 0
fi

TARGET="${1:-${BB_TARGET:-}}"
[[ -z "$TARGET" ]] && die "missing target"

BASE="$HOME/bounty/$TARGET"
mkdir -p "$BASE"/recon "$BASE"/enum "$BASE"/vulns/proto-pollution "$BASE"/vulns/xss

log "$c_amber" "Stage 1: URL collection"
(waybackurls "$TARGET"; gau "$TARGET" --mc 200,301,302) | awk 'NF' | sort -u > "$BASE/recon/all_urls.txt"

log "$c_amber" "Stage 2: Parameter mining"
cat "$BASE/recon/all_urls.txt" | rg -o "[?&][^=]+=" | sed 's/[?&]//' | sort -u > "$BASE/enum/params.txt" || true

log "$c_amber" "Stage 3: JS file collection"
rg -i '\.js' "$BASE/recon/all_urls.txt" | sort -u > "$BASE/enum/js-files.txt" || true

log "$c_amber" "Stage 4: JS analysis"
~/.config/wezterm/scripts/proto-pollution/pp-gadget-finder.py -d "$BASE/enum/js-files.txt" || true
python3 SecretFinder.py -i "https://$TARGET" -e -o "$BASE/enum/secrets.txt" || true

log "$c_amber" "Stage 5: XSS candidates"
cat "$BASE/recon/all_urls.txt" | gxss -c 150 | tee "$BASE/enum/gxss_candidates.txt" >/dev/null || true

log "$c_amber" "Stage 6: Proto pollution"
~/.config/wezterm/scripts/proto-pollution/ppfuzz-run.sh -f "$BASE/recon/all_urls.txt" || true

log "$c_green" "NG recon complete"
~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "NG-RECON complete for $TARGET" || true
exit 0
