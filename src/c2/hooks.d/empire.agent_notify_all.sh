#!/bin/bash
# Hook: When Empire gets a new agent, alert all devices
HOSTNAME=$(echo "$C2_DATA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('hostname','?'))" 2>/dev/null)
IP=$(echo "$C2_DATA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('external_ip','?'))" 2>/dev/null)
MSG="Empire agent: $HOSTNAME ($IP)"

# Alert via all channels
for target in phone laptop tower; do
  ssh -o ConnectTimeout=3 -o BatchMode=yes "$target" \
    "echo '[$(date -Iseconds)] $MSG' >> ~/c2/remote_alerts.log" 2>/dev/null &
done
