#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bb-init.sh <target>
Initializes bug bounty workspace directories and environment vars.
USAGE
}

if [[ ${1:-} == "-h" || ${1:-} == "" ]]; then
  usage
  exit 2
fi

target="$1"
base="$HOME/bounty/$target"

c() { printf "\033[38;2;%s;%s;%sm" "$1" "$2" "$3"; }
reset() { printf "\033[0m"; }

ts() { date '+[%H:%M:%S]'; }

log() { echo "$(ts) $(c 212 200 168)$*$(reset)"; }
trap 'log "Interrupted"; exit 3' INT

mkdir -p "$base"/{recon,enum,vulns/{xss,proto-pollution,sqli,idor,ssrf,open-redirect,rce},http-log,incoming,reports,burp}
mkdir -p "$base/recon/screenshots"

for f in recon/subs.txt recon/live_hosts.txt recon/ports.txt recon/dns.txt enum/dirs.txt enum/params.txt enum/vhosts.txt enum/js-files.txt; do
  mkdir -p "$(dirname "$base/$f")"
  : > "$base/$f"
done

if [[ ! -f "$base/notes.md" ]]; then
  cat <<EOF_NOTES > "$base/notes.md"
# $target

Date: $(date '+%Y-%m-%d')
Scope: 

## Recon
- 

## Findings
- 
EOF_NOTES
fi

export BB_TARGET="$target"
export BB_DIR="$base"
export BB_SCOPE_FILE="$base/scope.txt"

printf '%s\n' "$target" > "$HOME/.bb_target_current"

if [[ -n ${WEZTERM_EXECUTABLE:-} ]] && command -v wezterm >/dev/null 2>&1; then
  wezterm cli spawn --workspace BB-RECON >/dev/null 2>&1 || true
fi

log "Initialized $base"

if command -v "$HOME/.config/wezterm/scripts/kde-connect/kdc-notify.sh" >/dev/null 2>&1; then
  "$HOME/.config/wezterm/scripts/kde-connect/kdc-notify.sh" "BB init complete for $target" || true
fi

exit 0
