#!/usr/bin/env bash
# @32014SRG
# Usage: bb-recon.sh <target>
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
  echo "Usage: bb-recon.sh <target>"; exit 0
fi

TARGET="${1:-${BB_TARGET:-}}"
[[ -z "$TARGET" ]] && die "missing target"

BASE="$HOME/bounty/$TARGET"
mkdir -p "$BASE"/recon "$BASE"/screenshots "$BASE"/vulns

log "$c_amber" "Stage 1: subdomain discovery"
(subfinder -d "$TARGET" -all -recursive -silent; sublist3r -d "$TARGET" -t 20 -o /tmp/sublist3r.$$; cat /tmp/sublist3r.$$) \
  | awk 'NF' | sort -u | tee "$BASE/recon/subs.txt" >/dev/null

log "$c_amber" "Stage 2: DNS resolution"
dnsx -a -cname -resp -l "$BASE/recon/subs.txt" -o "$BASE/recon/dns.txt" || true
awk '/A\t/ {print $1}' "$BASE/recon/dns.txt" | sort -u > "$BASE/recon/ip_list.txt" || true

log "$c_amber" "Stage 3: HTTP probing"
cat "$BASE/recon/subs.txt" | httpx -silent -sc -title -tech -ip -o "$BASE/recon/live.txt" || true

log "$c_amber" "Stage 4: Port scanning"
if [[ -s "$BASE/recon/ip_list.txt" ]]; then
  nmap -iL "$BASE/recon/ip_list.txt" --top-ports 1000 -T4 -oN "$BASE/recon/ports.txt" || true
fi

log "$c_amber" "Stage 5: Screenshots"
~/.config/wezterm/scripts/bb/bb-screenshot.sh "$BASE/recon/live.txt" || true

log "$c_amber" "Stage 6: Nuclei"
~/.config/wezterm/scripts/nuclei/nuclei-bb.sh "$BASE/recon/live.txt" || true

count=$(wc -l < "$BASE/recon/live.txt" | tr -d ' ')
log "$c_green" "Done. Live hosts: $count"

~/.config/wezterm/scripts/kde-connect/kdc-notify.sh "BB-RECON complete for $TARGET (live: $count)" || true
exit 0
