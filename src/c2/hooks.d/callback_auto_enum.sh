#!/bin/bash
# Hook: Auto-enumerate the source IP of any OOB callback
SRC_IP=$(echo "$C2_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin).get('src_ip',''))" 2>/dev/null)
[ -z "$SRC_IP" ] && exit 0
[ "$SRC_IP" = "127.0.0.1" ] && exit 0

OUT="$C2_HOME/callbacks/enum_${SRC_IP}_$(date +%s).txt"
{
  echo "=== AUTO ENUM: $SRC_IP ==="
  echo "--- Reverse DNS ---"
  host "$SRC_IP" 2>/dev/null || dig -x "$SRC_IP" +short 2>/dev/null
  echo "--- Whois (short) ---"
  whois "$SRC_IP" 2>/dev/null | grep -iE "orgname|org-name|netname|country|descr" | head -10
} > "$OUT" 2>&1 &
