#!/bin/bash
# Hook: Alert on WiFi anomalies (rogue AP, deauth)
# Matches: security/* events

case "$C2_EVENT" in
  security.wifi_rogue|security.wifi_deauth|security/wifi_rogue|security/wifi_deauth)
    ;;
  *)
    exit 0
    ;;
esac

MSG="WIFI ALERT: $C2_EVENT - $(echo "$C2_DATA" | head -c 200)"
echo "[$C2_TIMESTAMP] $MSG" >> "$C2_HOME/logs/wifi_alerts.log"

# Termux notification
if [ -d "/data/data/com.termux" ]; then
  termux-notification --title "WiFi Security Alert" --content "$MSG" \
    --priority max --vibrate 500,200,500 --led-color ff0000 --group c2wifi 2>/dev/null
fi
