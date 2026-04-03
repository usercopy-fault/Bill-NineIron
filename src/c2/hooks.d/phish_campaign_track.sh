#!/bin/bash
# Hook: Track phishing campaign hits and captures
# Matches: phish/* events

case "$C2_EVENT" in
  phish.landing_hit|phish.campaign_created|phish/landing_hit)
    ;;
  *)
    exit 0
    ;;
esac

echo "[$C2_TIMESTAMP] $C2_EVENT: $(echo "$C2_DATA" | head -c 200)" >> "$C2_HOME/logs/phish_tracking.log"
