#!/usr/bin/env bash
set -euo pipefail

mode="${1:-open}"

ROOTS=(
  "/home/sbu/Videos"
  "/home/sbu/Music"
)

pick() {
  local list
  list="$(find "${ROOTS[@]}" -type f \( -name '*.js' -o -name '*.sh' \) 2>/dev/null | sort)"
  if [[ -z "$list" ]]; then
    return 1
  fi
  if [[ ! -t 1 ]] || ! command -v fzf >/dev/null 2>&1; then
    printf '%s\n' "$list" | head -n1
    return 0
  fi
  printf '%s\n' "$list" \
    | fzf --height 80% --layout=reverse --prompt="bb-media> " --preview='sed -n "1,120p" {}'
}

target="$(pick || true)"
[[ -n "${target:-}" ]] || exit 0

case "$mode" in
  open)
    exec nvim "$target"
    ;;
  check)
    if [[ "$target" == *.js ]]; then
      exec node --check "$target"
    fi
    if [[ "$target" == *.sh ]]; then
      exec bash -n "$target"
    fi
    ;;
  copy-path)
    if command -v wl-copy >/dev/null 2>&1; then
      printf '%s' "$target" | wl-copy
      printf 'Copied path to clipboard: %s\n' "$target"
    elif command -v xclip >/dev/null 2>&1; then
      printf '%s' "$target" | xclip -selection clipboard
      printf 'Copied path to clipboard: %s\n' "$target"
    else
      printf '%s\n' "$target"
    fi
    ;;
  run)
    if [[ "$target" == *.sh ]]; then
      exec bash "$target"
    fi
    if [[ "$target" == *.js ]]; then
      exec node "$target"
    fi
    ;;
  *)
    printf 'Usage: %s [open|check|copy-path|run]\n' "$0" >&2
    exit 2
    ;;
esac
