#!/bin/bash
# Hook: Notify on file exfiltration uploads
# Matches: exfil/* events

case "$C2_EVENT" in
  exfil.*|exfil/*)
    ;;
  *)
    exit 0
    ;;
esac

MSG="EXFIL: $(echo "$C2_DATA" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f\"{d.get('filename','?')} ({d.get('size','?')} bytes) from {d.get('src_ip','?')}\")" 2>/dev/null || echo "$C2_DATA" | head -c 120)"
echo "[$C2_TIMESTAMP] $MSG" >> "$C2_HOME/logs/exfil.log"

if command -v notify-send &>/dev/null; then
  notify-send -u critical "Exfil Upload" "$MSG" 2>/dev/null
fi
