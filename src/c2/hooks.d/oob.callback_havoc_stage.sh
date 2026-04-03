#!/bin/bash
# Hook: Log OOB callback details for Havoc correlation
# When a callback comes in, check if it matches a Havoc demon token
TOKEN=$(echo "$C2_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
[ -z "$TOKEN" ] && exit 0

# Log token correlation
echo "[$(date -Iseconds)] CALLBACK TOKEN: $TOKEN" >> "$C2_HOME/logs/token_correlation.log"
echo "$C2_DATA" >> "$C2_HOME/logs/token_correlation.log"
