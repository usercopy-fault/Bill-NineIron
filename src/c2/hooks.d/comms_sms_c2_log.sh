#!/bin/bash
# Hook: Log SMS C2 commands
# Matches: comms/* events

case "$C2_EVENT" in
  comms.*|comms/*)
    ;;
  *)
    exit 0
    ;;
esac

echo "[$C2_TIMESTAMP] $C2_EVENT: $(echo "$C2_DATA" | head -c 300)" >> "$C2_HOME/logs/comms.log"
