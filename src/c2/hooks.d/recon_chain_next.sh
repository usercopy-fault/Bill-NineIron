#!/bin/bash
# Hook: Chain recon stages — when one completes, trigger next
STAGE=$(echo "$C2_DATA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('stage',''))" 2>/dev/null)
TARGET=$(echo "$C2_DATA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('target',''))" 2>/dev/null)
[ -z "$TARGET" ] && exit 0

case "$STAGE" in
  subdomain)
    # After subdomain enum, start port scan
    curl -s "http://127.0.0.1:9800/recon/ports" \
      -d "{\"target\":\"$TARGET\",\"stage\":\"ports\",\"prev\":\"subdomain\"}" &
    ;;
  ports)
    # After port scan, start service fingerprint
    curl -s "http://127.0.0.1:9800/recon/fingerprint" \
      -d "{\"target\":\"$TARGET\",\"stage\":\"fingerprint\",\"prev\":\"ports\"}" &
    ;;
  fingerprint)
    # After fingerprint, start vuln scan
    curl -s "http://127.0.0.1:9800/recon/vulnscan" \
      -d "{\"target\":\"$TARGET\",\"stage\":\"vulnscan\",\"prev\":\"fingerprint\"}" &
    ;;
esac
