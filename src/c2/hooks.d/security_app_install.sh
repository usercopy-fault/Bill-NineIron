#!/bin/bash
# Hook: Alert on new app installations
# Matches: security/* events

case "$C2_EVENT" in
  security.app_install|security/app_install)
    ;;
  *)
    exit 0
    ;;
esac

MSG="NEW APP: $(echo "$C2_DATA" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('new_apps','?'))" 2>/dev/null || echo "$C2_DATA" | head -c 120)"
echo "[$C2_TIMESTAMP] $MSG" >> "$C2_HOME/logs/app_installs.log"

if [ -d "/data/data/com.termux" ]; then
  termux-notification --title "New App Installed" --content "$MSG" \
    --priority high --vibrate 200 --led-color ffaa00 --group c2apps 2>/dev/null
fi
