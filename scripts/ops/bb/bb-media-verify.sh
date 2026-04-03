#!/usr/bin/env bash
set -u

ROOTS=(
  "/home/sbu/Videos"
  "/home/sbu/Music"
)

if [[ "${1:-}" == "--include-blackswantear" ]]; then
  ROOTS+=(
    "/home/sbu/BlackSwanTear/tooling/Videos"
    "/home/sbu/BlackSwanTear/tooling/Music"
  )
fi

ok=0
fail=0

check_js() {
  local f="$1"
  if node --check "$f" >/dev/null 2>&1; then
    printf 'OK   JS  %s\n' "$f"
    ok=$((ok + 1))
  else
    printf 'FAIL JS  %s\n' "$f"
    node --check "$f" 2>&1 | sed -n '1,3p'
    fail=$((fail + 1))
  fi
}

check_sh() {
  local f="$1"
  if bash -n "$f" >/dev/null 2>&1; then
    printf 'OK   SH  %s\n' "$f"
    ok=$((ok + 1))
  else
    printf 'FAIL SH  %s\n' "$f"
    bash -n "$f" 2>&1 | sed -n '1,3p'
    fail=$((fail + 1))
  fi
}

while IFS= read -r -d '' file; do
  case "$file" in
    *.js) check_js "$file" ;;
    *.sh) check_sh "$file" ;;
  esac
done < <(find "${ROOTS[@]}" -type f \( -name '*.js' -o -name '*.sh' \) -print0 2>/dev/null)

printf '\nSummary: %d ok, %d failed\n' "$ok" "$fail"

if (( fail > 0 )); then
  exit 1
fi

