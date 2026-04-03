#!/bin/bash
# Hook: Trigger auto-sync on version mismatch
# Matches: system/* events

case "$C2_EVENT" in
  system.version_mismatch|system/version_mismatch)
    ;;
  *)
    exit 0
    ;;
esac

NODE=$(echo "$C2_DATA" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('node',''))" 2>/dev/null)
echo "[$C2_TIMESTAMP] Version mismatch on $NODE — triggering sync" >> "$C2_HOME/logs/version_sync.log"

# Only auto-sync if hooks CLI is available
if [ -x "$HOME/bin/hooks" ]; then
  "$HOME/bin/hooks" sync "$NODE" >> "$C2_HOME/logs/version_sync.log" 2>&1 &
fi
