#!/bin/bash
# Hook: Send SMS on any critical-urgency event
# Matches: all events (all_ prefix)
# Filters: only fires for critical event types

# Only act on critical event types
case "$C2_EVENT" in
  cred.*|vuln.*|security/arp_spoof|security/wifi_rogue|exfil.*|oob.callback)
    ;;
  *)
    exit 0
    ;;
esac

SMS_NUM=$(python3 -c "import json; cfg=json.load(open('$C2_HOME/config.json')); devs=cfg.get('alert_devices',[]); print(devs[0].split('@')[-1] if devs else '')" 2>/dev/null)
[ -z "$SMS_NUM" ] && exit 0

# If on Termux, send SMS directly
if [ -d "/data/data/com.termux" ]; then
  MSG="[C2 ALERT] $C2_EVENT: $(echo "$C2_DATA" | head -c 120)"
  termux-sms-send -n "$SMS_NUM" "$MSG" 2>/dev/null
fi
