#!/bin/bash
# Hook: Critical alert on ARP spoof detection
# Matches: security/* events

case "$C2_EVENT" in
  security.arp_spoof|security/arp_spoof)
    ;;
  *)
    exit 0
    ;;
esac

MSG="ARP SPOOF DETECTED: $(echo "$C2_DATA" | head -c 200)"
echo "[$C2_TIMESTAMP] CRITICAL: $MSG" >> "$C2_HOME/logs/arp_alerts.log"

# Termux: high-priority notification + vibrate
if [ -d "/data/data/com.termux" ]; then
  termux-notification --title "ARP SPOOF ALERT" --content "$MSG" \
    --priority max --vibrate 1000,500,1000,500,1000 --led-color ff0000 --group c2arp 2>/dev/null
  termux-toast -b red -c white "ARP SPOOF: Check network!" 2>/dev/null
fi
