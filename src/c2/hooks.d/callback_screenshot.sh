#!/bin/bash
# Hook: Take screenshot on OOB callback (evidence capture)
TS=$(date +%Y%m%d_%H%M%S)
if command -v termux-notification &>/dev/null; then
  termux-vibrate -d 500
fi
if command -v scrot &>/dev/null; then
  scrot "$C2_HOME/callbacks/screenshot_${TS}.png" 2>/dev/null
fi
echo "$C2_DATA" > "$C2_HOME/callbacks/callback_${TS}.json"
