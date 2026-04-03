#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║  C2 Beacon — Lightweight Heartbeat & DNS Fallback    ║
║  When SSH dies, this keeps nodes visible              ║
║  Modes: heartbeat (HTTP), dns-beacon, dormant         ║
╚══════════════════════════════════════════════════════╝

Usage:
  beacon.py serve                 # Run beacon listener (on C2 primary)
  beacon.py beat                  # Send heartbeats (on each node)
  beacon.py status                # Show all node statuses
  beacon.py dormant <interval>    # Go dormant, beacon every N seconds
"""

import json
import os
import sys
import time
import signal
import socket
import sqlite3
import logging
import subprocess
import traceback
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from threading import Thread, Lock

# ── Config ───────────────────────────────────────
BASE_DIR = Path(os.environ.get("C2_HOME", Path.home() / "c2"))
NODES_FILE = BASE_DIR / "nodes.json"
DB_PATH = BASE_DIR / "beacon.db"
BEACON_PORT = 9802
DNS_BEACON_PORT = 5353
HEARTBEAT_INTERVAL = 30       # seconds between heartbeats
DORMANT_INTERVAL = 300        # 5 min when dormant
IS_TERMUX = os.path.exists("/data/data/com.termux")

# Ensure dirs exist
for _d in [BASE_DIR, BASE_DIR / "logs"]:
    _d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BEACON] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(BASE_DIR / "beacon.log", mode="a"),
    ],
)
log = logging.getLogger("beacon")
_db_lock = Lock()


# ── Safe DB Operations ──────────────────────────
def db_exec(db, query, params=(), commit=True):
    """Thread-safe database execute with retry."""
    with _db_lock:
        try:
            cur = db.execute(query, params)
            if commit:
                db.commit()
            return cur
        except sqlite3.OperationalError as e:
            if "locked" in str(e):
                time.sleep(0.1)
                try:
                    cur = db.execute(query, params)
                    if commit:
                        db.commit()
                    return cur
                except Exception as e2:
                    log.error(f"DB retry failed: {e2}")
            else:
                log.error(f"DB error: {e}")
            return None
        except Exception as e:
            log.error(f"DB error: {e}")
            return None


# ── Beacon Database ──────────────────────────────
def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("""
        CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            node_name TEXT NOT NULL,
            node_ip TEXT,
            method TEXT DEFAULT 'http',
            data TEXT,
            latency_ms INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS node_status (
            node_name TEXT PRIMARY KEY,
            last_seen TEXT NOT NULL,
            last_ip TEXT,
            method TEXT DEFAULT 'http',
            status TEXT DEFAULT 'online',
            uptime_secs INTEGER DEFAULT 0,
            extra TEXT DEFAULT '{}'
        )
    """)
    db.commit()
    return db


# ── Node Identity ────────────────────────────────
def get_node_name():
    """Determine this node's name from nodes.json."""
    try:
        if not NODES_FILE.exists():
            return socket.gethostname()
        with open(NODES_FILE) as f:
            nodes = json.load(f).get("nodes", {})
    except (json.JSONDecodeError, OSError) as e:
        log.warning(f"Cannot read nodes.json: {e}")
        return socket.gethostname()

    hostname = socket.gethostname()
    for name, cfg in nodes.items():
        if cfg.get("hostname") == hostname:
            return name

    # Check by IP
    local_ips = []
    try:
        result = subprocess.run(
            ["hostname", "-I"], text=True, timeout=5, capture_output=True
        )
        if result.returncode == 0:
            local_ips = result.stdout.strip().split()
    except (OSError, subprocess.TimeoutExpired):
        pass

    for name, cfg in nodes.items():
        if cfg.get("tailscale") in local_ips or cfg.get("lan") in local_ips:
            return name
    if IS_TERMUX:
        return "phone"
    return hostname


def load_nodes():
    """Safely load nodes config."""
    try:
        if NODES_FILE.exists():
            with open(NODES_FILE) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.warning(f"Cannot load nodes.json: {e}")
    return {"nodes": {}, "ollama_priority": []}


# ── Heartbeat Sender ─────────────────────────────
def send_heartbeat(targets, node_name, interval=HEARTBEAT_INTERVAL, dormant=False):
    """Continuously send heartbeats to C2 servers."""
    start_time = time.time()
    log.info(f"Heartbeat loop starting: targets={targets}, interval={interval}s, dormant={dormant}")

    while True:
        uptime = int(time.time() - start_time)
        payload = {
            "node": node_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime": uptime,
            "dormant": dormant,
            "method": "http",
        }

        # Gather local info
        try:
            payload["load"] = os.getloadavg()[0]
        except (OSError, AttributeError):
            pass

        # Version from config.json
        try:
            conf_path = BASE_DIR / "config.json"
            if conf_path.exists():
                with open(conf_path) as f:
                    cfg = json.load(f)
                payload["version"] = cfg.get("version", "0.0.0")
        except (json.JSONDecodeError, OSError):
            pass

        # Location enrichment (Termux only)
        if IS_TERMUX and not dormant:
            try:
                loc_result = subprocess.run(
                    ["termux-location", "-p", "network", "-r", "once"],
                    capture_output=True, text=True, timeout=15
                )
                if loc_result.returncode == 0 and loc_result.stdout.strip():
                    loc = json.loads(loc_result.stdout)
                    payload["location"] = {
                        "lat": loc.get("latitude"),
                        "lon": loc.get("longitude"),
                        "accuracy": loc.get("accuracy"),
                    }
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
                pass

        sent = False
        # Try HTTP heartbeat to each target
        for target in targets:
            try:
                data = json.dumps(payload).encode()
                req = urllib.request.Request(
                    f"http://{target}:{BEACON_PORT}/heartbeat",
                    data=data,
                    headers={"Content-Type": "application/json"},
                )
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=5) as resp:
                    latency = int((time.time() - t0) * 1000)
                    log.info(f"Heartbeat -> {target} OK ({latency}ms)")
                    sent = True
                    break  # Success, skip remaining targets
            except Exception as e:
                log.debug(f"Heartbeat -> {target} failed: {e}")

        # If HTTP failed, try DNS beacon to all targets
        if not sent:
            for target in targets:
                try:
                    dns_beacon(target, node_name, uptime)
                    log.info(f"DNS beacon -> {target}")
                except Exception as e:
                    log.debug(f"DNS beacon -> {target} failed: {e}")

        actual_interval = DORMANT_INTERVAL if dormant else interval
        time.sleep(actual_interval)


def dns_beacon(target_ip, node_name, uptime):
    """
    Send a DNS-style UDP beacon. Minimal footprint.
    Uses UDP port 5353 (mDNS-like, blends with normal traffic).
    """
    magic = b"\xc2\xbe\xac\x01"  # C2 beacon magic
    payload = magic + json.dumps({
        "n": node_name[:10],
        "u": uptime,
        "t": int(time.time()),
    }).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(payload, (target_ip, DNS_BEACON_PORT))
    except (OSError, socket.error) as e:
        log.debug(f"DNS send to {target_ip} failed: {e}")
    finally:
        sock.close()


# ── Threaded HTTP Server ─────────────────────────
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── Beacon Listener (HTTP) ───────────────────────
class BeaconHandler(BaseHTTPRequestHandler):
    db = None

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        try:
            self._handle_post()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            log.error(f"Beacon POST error: {e}")
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

    def _handle_post(self):
        if self.path != "/heartbeat":
            self.send_response(404)
            self.end_headers()
            return

        # Read body safely
        try:
            cl = self.headers.get("Content-Length", "0")
            content_length = int(cl) if cl.isdigit() else 0
        except (ValueError, TypeError):
            content_length = 0

        body = ""
        if 0 < content_length < 1_000_000:
            try:
                body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            except OSError:
                pass

        src_ip = self.client_address[0]

        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            data = {"raw": body[:500]}

        node_name = str(data.get("node", "unknown"))[:50]
        ts = datetime.now(timezone.utc).isoformat()

        # Log heartbeat
        db_exec(self.db,
            "INSERT INTO heartbeats (timestamp, node_name, node_ip, method, data) VALUES (?,?,?,?,?)",
            (ts, node_name, src_ip, str(data.get("method", "http")), json.dumps(data)[:2000]),
        )

        # Update node status
        extra = {}
        for k, v in data.items():
            if k not in ("node", "timestamp", "uptime", "dormant", "method"):
                extra[k] = v
        db_exec(self.db, """
            INSERT INTO node_status (node_name, last_seen, last_ip, method, status, uptime_secs, extra)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(node_name) DO UPDATE SET
                last_seen=excluded.last_seen,
                last_ip=excluded.last_ip,
                method=excluded.method,
                status=excluded.status,
                uptime_secs=excluded.uptime_secs,
                extra=excluded.extra
        """, (
            node_name, ts, src_ip,
            str(data.get("method", "http")),
            "dormant" if data.get("dormant") else "online",
            int(data.get("uptime", 0)) if str(data.get("uptime", 0)).isdigit() else 0,
            json.dumps(extra)[:1000],
        ))

        log.info(f"Heartbeat <- {node_name} ({src_ip}) uptime={data.get('uptime',0)}s")

        # Notify hookserver (non-blocking, don't care if it fails)
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    "http://127.0.0.1:9800/beacon/heartbeat",
                    data=json.dumps({"node": node_name, "ip": src_ip, "method": "http"}).encode(),
                    headers={"Content-Type": "application/json"},
                ),
                timeout=2,
            )
        except Exception:
            pass

        # Build response with pending messages
        response = {"ack": True, "ts": ts}

        # Fetch pending messages for this node from hookserver
        try:
            msg_req = urllib.request.Request(
                f"http://127.0.0.1:9800/msg/pending/{node_name}",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(msg_req, timeout=2) as msg_resp:
                pending = json.loads(msg_resp.read())
                if pending:
                    response["messages"] = pending
                    log.info(f"Delivering {len(pending)} messages to {node_name}")
        except Exception:
            pass

        # Version check — compare node version with local config
        node_version = str(data.get("version", ""))
        if node_version:
            try:
                conf_path = BASE_DIR / "config.json"
                if conf_path.exists():
                    with open(conf_path) as f:
                        local_cfg = json.load(f)
                    server_version = local_cfg.get("version", "0.0.0")
                    if node_version != server_version:
                        response["version_mismatch"] = True
                        response["server_version"] = server_version
                        log.warning(f"Version mismatch: {node_name}={node_version} server={server_version}")
                        # Fire version mismatch event
                        try:
                            urllib.request.urlopen(
                                urllib.request.Request(
                                    "http://127.0.0.1:9800/system/version_mismatch",
                                    data=json.dumps({"node": node_name, "node_version": node_version, "server_version": server_version}).encode(),
                                    headers={"Content-Type": "application/json"},
                                ),
                                timeout=2,
                            )
                        except Exception:
                            pass
            except (json.JSONDecodeError, OSError):
                pass

        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        try:
            self._handle_get()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            log.error(f"Beacon GET error: {e}")

    def _handle_get(self):
        if self.path == "/status":
            cur = db_exec(self.db, "SELECT * FROM node_status ORDER BY node_name", commit=False)
            if cur:
                rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
            else:
                rows = []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(rows, indent=2, default=str).encode())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "alive", "service": "beacon"}).encode())
        else:
            self.send_response(404)
            self.end_headers()


# ── DNS Beacon Listener (UDP) ────────────────────
def dns_listener(db):
    """Listen for DNS-style UDP beacons on port 5353."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", DNS_BEACON_PORT))
    except OSError as e:
        log.warning(f"DNS beacon listener failed to bind :{DNS_BEACON_PORT}: {e}")
        log.warning("Continuing without DNS beacon listener")
        return

    log.info(f"DNS beacon listener on UDP :{DNS_BEACON_PORT}")
    magic = b"\xc2\xbe\xac\x01"

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if not data.startswith(magic):
                continue  # Not our beacon
            payload = data[4:]
            try:
                beacon = json.loads(payload)
            except (json.JSONDecodeError, ValueError):
                continue

            node_name = str(beacon.get("n", "unknown"))[:50]
            src_ip = addr[0]
            ts = datetime.now(timezone.utc).isoformat()
            uptime = int(beacon.get("u", 0)) if str(beacon.get("u", 0)).isdigit() else 0

            db_exec(db,
                "INSERT INTO heartbeats (timestamp, node_name, node_ip, method, data) VALUES (?,?,?,?,?)",
                (ts, node_name, src_ip, "dns", json.dumps(beacon)[:1000]),
            )
            db_exec(db, """
                INSERT INTO node_status (node_name, last_seen, last_ip, method, status, uptime_secs)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(node_name) DO UPDATE SET
                    last_seen=excluded.last_seen, last_ip=excluded.last_ip,
                    method='dns', status='beacon-only'
            """, (node_name, ts, src_ip, "dns", "beacon-only", uptime))

            log.info(f"DNS beacon <- {node_name} ({src_ip})")
        except Exception as e:
            log.debug(f"DNS listener error: {e}")
            time.sleep(1)  # Avoid tight loop on persistent errors


# ── Stale Node Checker ───────────────────────────
def stale_checker(db):
    """Mark nodes as offline if no heartbeat for 3x interval."""
    while True:
        time.sleep(HEARTBEAT_INTERVAL * 3)
        try:
            cur = db_exec(db, "SELECT node_name, last_seen FROM node_status WHERE status NOT IN ('offline')", commit=False)
            if not cur:
                continue
            for row in cur.fetchall():
                node, last = row
                try:
                    last_dt = datetime.fromisoformat(str(last))
                    age = (datetime.now(timezone.utc) - last_dt).total_seconds()
                    if age > HEARTBEAT_INTERVAL * 3:
                        db_exec(db, "UPDATE node_status SET status='offline' WHERE node_name=?", (node,))
                        log.warning(f"Node {node} marked offline (last seen {int(age)}s ago)")

                        # Notify hookserver
                        try:
                            urllib.request.urlopen(
                                urllib.request.Request(
                                    "http://127.0.0.1:9800/beacon/offline",
                                    data=json.dumps({"node": node, "last_seen": str(last)}).encode(),
                                    headers={"Content-Type": "application/json"},
                                ),
                                timeout=2,
                            )
                        except Exception:
                            pass
                except (ValueError, TypeError) as e:
                    log.debug(f"Stale check parse error for {node}: {e}")
        except Exception as e:
            log.debug(f"Stale check error: {e}")


# ── Status Display ───────────────────────────────
def show_status():
    if not DB_PATH.exists():
        print("No beacon data yet. Start with: beacon.py serve")
        return

    try:
        db = sqlite3.connect(str(DB_PATH))
        cur = db.execute("SELECT * FROM node_status ORDER BY node_name")
        cols = [c[0] for c in cur.description]
        rows = cur.fetchall()
        db.close()
    except (sqlite3.Error, OSError) as e:
        print(f"Cannot read beacon DB: {e}")
        return

    if not rows:
        print("No nodes reporting yet.")
        return

    colors = {"online": "\033[0;32m", "dormant": "\033[0;33m", "beacon-only": "\033[0;36m", "offline": "\033[0;31m"}
    RST = "\033[0m"

    print(f"\033[1mBeacon Status\033[0m")
    print()
    for row in rows:
        d = dict(zip(cols, row))
        c = colors.get(str(d.get("status", "")), "")
        last_seen = str(d.get("last_seen", "?"))[:19]
        last_ip = str(d.get("last_ip", "?"))
        method = str(d.get("method", "?"))
        uptime = d.get("uptime_secs", 0)
        node = str(d.get("node_name", "?"))
        status = str(d.get("status", "?"))
        print(f"  {c}{status:12}{RST}  \033[1m{node:10}\033[0m  "
              f"ip={last_ip:18}  via={method:5}  "
              f"up={uptime}s  last={last_seen}")


# ── Get Targets ──────────────────────────────────
def get_targets(node_name):
    """Get beacon target IPs from nodes.json."""
    targets = []
    ncfg = load_nodes()
    for name, node in ncfg.get("nodes", {}).items():
        if name == node_name:
            continue
        if "c2-server" in node.get("capabilities", []):
            if node.get("lan"):
                targets.append(node["lan"])
            if node.get("tailscale"):
                targets.append(node["tailscale"])
    if not targets:
        targets = ["127.0.0.1"]
    return targets


# ── Main ─────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    # Signal handling
    def shutdown_handler(signum, frame):
        log.info(f"Signal {signum}, shutting down beacon")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    if cmd == "serve":
        db = init_db()
        log.info(f"Beacon server starting on :{BEACON_PORT} (HTTP) + :{DNS_BEACON_PORT} (UDP)")

        # HTTP listener
        try:
            BeaconHandler.db = db
            http = ThreadedHTTPServer(("0.0.0.0", BEACON_PORT), BeaconHandler)
            Thread(target=http.serve_forever, daemon=True).start()
            log.info(f"HTTP beacon listener on :{BEACON_PORT}")
        except OSError as e:
            log.error(f"Cannot bind beacon HTTP :{BEACON_PORT}: {e}")
            sys.exit(1)

        # UDP/DNS listener
        Thread(target=dns_listener, args=(db,), daemon=True).start()

        # Stale checker
        Thread(target=stale_checker, args=(db,), daemon=True).start()

        log.info("Beacon server online")
        while True:
            time.sleep(60)

    elif cmd == "beat":
        node_name = get_node_name()
        log.info(f"Starting heartbeat as '{node_name}'")
        targets = get_targets(node_name)
        log.info(f"Beacon targets: {targets}")
        send_heartbeat(targets, node_name)

    elif cmd == "dormant":
        try:
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else DORMANT_INTERVAL
        except ValueError:
            interval = DORMANT_INTERVAL
        node_name = get_node_name()
        log.info(f"Going dormant as '{node_name}', beacon every {interval}s")
        targets = get_targets(node_name)
        send_heartbeat(targets, node_name, interval=interval, dormant=True)

    elif cmd == "status":
        show_status()

    else:
        print(__doc__)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.critical(f"Fatal beacon error: {e}\n{traceback.format_exc()}")
        sys.exit(1)
