#!/usr/bin/env bash
# @32014SRG :: interactsh-watch.sh
# Runs interactsh-client (or falls back to nc), writes hits to /tmp/wezterm-status/
# so WezTerm picks them up within 2s and fires toast notifications.
#
# Usage:
#   interactsh-watch.sh                   # use public oast.fun
#   interactsh-watch.sh oast.pro          # use public oast.pro
#   interactsh-watch.sh https://your.host # use self-hosted server
#
# Install interactsh-client (if needed):
#   go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
#   # or: ~/venv/bin/pip install interactsh  (Python client)

STATUS_DIR="/tmp/wezterm-status"
LOG_FILE="$STATUS_DIR/callbacks.log"
COUNT_FILE="$STATUS_DIR/callback_count"
NOTIFY_FILE="$STATUS_DIR/callback_notify"
LAST_FILE="$STATUS_DIR/callback_last"
COLLAB_FILE="$STATUS_DIR/callbacks"

mkdir -p "$STATUS_DIR"
echo "0" > "$COUNT_FILE"
echo "OFF" > "$COLLAB_FILE"
: > "$LOG_FILE"

_bump() {
  local type="$1" remote="$2" detail="$3"
  local count
  count=$(( $(cat "$COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
  echo "$count" > "$COUNT_FILE"
  echo "${count}x" > "$COLLAB_FILE"
  printf '%s\n' "${type}:${remote}" > "$LAST_FILE"
  # Append to log
  printf '[%s] %s from %s\n%s\n---\n' \
    "$(date '+%H:%M:%S')" "$type" "$remote" "$detail" >> "$LOG_FILE"
  # Write notify file — WezTerm clears it after toasting
  printf '%s from %s' "$type" "$remote" > "$NOTIFY_FILE"
}

SERVER="${1:-}"

# ── interactsh-client (preferred) ────────────────────────────────────────────
if command -v interactsh-client >/dev/null 2>&1; then
  echo "[*] Starting interactsh-client${SERVER:+ → $SERVER}"
  ARGS=(-json -v)
  [ -n "$SERVER" ] && ARGS+=(-server "$SERVER")
  interactsh-client "${ARGS[@]}" 2>/dev/null | \
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" >> "$LOG_FILE.raw"
    protocol=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('protocol','?').upper())" 2>/dev/null || echo "HIT")
    remote=$(echo "$line"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('remote-address','?'))" 2>/dev/null || echo "?")
    _bump "$protocol" "$remote" "$line"
  done

# ── Python interactsh client (pip install interactsh) ────────────────────────
elif python3 -c "import interactsh" 2>/dev/null; then
  echo "[*] Using Python interactsh client${SERVER:+ → $SERVER}"
  python3 - "$SERVER" <<'PYEOF'
import sys, time, json
try:
    from interactsh.client import InteractshClient
    url = sys.argv[1] if len(sys.argv) > 1 else None
    c = InteractshClient(server=url) if url else InteractshClient()
    print(f"[*] OOB URL: {c.correlation_id}.{c.server}")
    while True:
        for hit in (c.poll() or []):
            t = hit.get("protocol","HIT").upper()
            r = hit.get("remote-address","?")
            with open("/tmp/wezterm-status/callback_count") as f:
                n = int(f.read().strip() or 0)
            n += 1
            open("/tmp/wezterm-status/callback_count","w").write(str(n))
            open("/tmp/wezterm-status/callbacks","w").write(f"{n}x")
            open("/tmp/wezterm-status/callback_last","w").write(f"{t}:{r}")
            open("/tmp/wezterm-status/callback_notify","w").write(f"{t} from {r}")
            with open("/tmp/wezterm-status/callbacks.log","a") as lg:
                lg.write(f"[{time.strftime('%H:%M:%S')}] {t} from {r}\n{json.dumps(hit)}\n---\n")
        time.sleep(2)
except KeyboardInterrupt:
    pass
PYEOF

# ── Fallback: nc listener ─────────────────────────────────────────────────────
else
  PORT="${COLLAB_PORT:-8888}"
  echo "[!] interactsh-client not found."
  echo "[!] Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  echo "[*] Falling back to nc listener on port $PORT"
  echo ""
  while true; do
    echo "[$(date '+%H:%M:%S')] Listening on 0.0.0.0:$PORT ..."
    DATA=$(nc -lvnp "$PORT" 2>&1)
    remote=$(echo "$DATA" | grep -oP 'from \K[\d.]+' | head -1 || echo "?")
    _bump "HTTP" "$remote" "$DATA"
    echo "[$(date '+%H:%M:%S')] Hit from $remote — restarting listener..."
  done
fi
