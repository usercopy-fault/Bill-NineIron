#!/usr/bin/env python3
"""TOWER C2 — Agent

Beacon loop. Picks up tasks. Posts results. Handles file transfers.
Stores its auth token in ~/.c2_token so it survives reboots.

Deploy to each machine that joins the tower:
  python3 agent.py --server http://100.64.0.10:8080

The agent auto-registers on first run and saves its token.
All communication is over Tailscale (encrypted WireGuard).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import time
from pathlib import Path

import requests

TOKEN_FILE   = Path.home() / ".c2_token"
CHUNK_SIZE   = 512 * 1024   # 512KB


def get_tailscale_ip() -> str:
    try:
        out = subprocess.check_output(["tailscale", "ip", "-4"], timeout=3)
        return out.decode().strip()
    except Exception:
        return ""


def get_git_version(repo: str) -> str:
    path = Path.home() / repo
    if not path.exists():
        return ""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            timeout=5,
        )
        return out.decode().strip()
    except Exception:
        return ""


def sysinfo() -> dict:
    return {
        "hostname":     platform.node(),
        "tailscale_ip": get_tailscale_ip(),
        "os":           platform.system().lower(),
        "arch":         platform.machine(),
        "kernel":       platform.release(),
        "username":     os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "is_root":      os.getuid() == 0 if hasattr(os, "getuid") else False,
    }


class Agent:
    def __init__(self, server: str, sleep: int = 5, jitter: float = 0.2):
        self.server  = server.rstrip("/")
        self.sleep   = sleep
        self.jitter  = jitter
        self.token   = self._load_or_register()
        self.headers = {"X-Agent-Token": self.token}
        self.tracked_repo = ""

    def _load_or_register(self) -> str:
        if TOKEN_FILE.exists():
            return TOKEN_FILE.read_text().strip()
        return self._register()

    def _register(self) -> str:
        info = sysinfo()
        resp = requests.post(
            f"{self.server}/api/register",
            json=info,
            timeout=10,
        )
        resp.raise_for_status()
        data  = resp.json()
        token = data["token"]
        TOKEN_FILE.write_text(token)
        TOKEN_FILE.chmod(0o600)
        print(f"[+] Registered as {data['agent_id']} — token saved to {TOKEN_FILE}")
        return token

    def run(self):
        print(f"[*] Beaconing to {self.server} every {self.sleep}s (+{int(self.jitter*100)}% jitter)")
        while True:
            try:
                self._beacon()
            except KeyboardInterrupt:
                print("\n[*] Agent stopped.")
                break
            except Exception as e:
                pass   # Silent fail — never crash the beacon loop

            delay = self.sleep * (1 + random.uniform(0, self.jitter))
            time.sleep(delay)

    def _beacon(self):
        info = sysinfo()
        info["git_version"] = get_git_version(self.tracked_repo) if self.tracked_repo else ""
        info["git_repo"]    = self.tracked_repo

        resp = requests.post(
            f"{self.server}/api/beacon",
            json=info,
            headers=self.headers,
            timeout=15,
        )
        if resp.status_code == 401:
            # Token revoked — re-register
            self.token   = self._register()
            self.headers = {"X-Agent-Token": self.token}
            return

        resp.raise_for_status()
        data  = resp.json()
        tasks = data.get("tasks", [])

        for task in tasks:
            self._execute(task)

    def _execute(self, task: dict):
        task_id = task["id"]
        ttype   = task.get("type", "shell")
        command = task.get("command", "")
        args    = task.get("args", {})

        stdout, stderr, exit_code = "", "", 0

        if ttype in ("shell", "deploy"):
            stdout, stderr, exit_code = self._run_shell(command)

            # If this is a deploy, update tracked repo
            if ttype == "deploy" and exit_code == 0:
                repo = args.get("repo", "")
                if repo:
                    self.tracked_repo = repo

        elif ttype == "file_download":
            stdout, stderr, exit_code = self._upload_file(
                task_id, args.get("path", command)
            )

        elif ttype == "file_upload":
            stdout, stderr, exit_code = self._receive_file(
                task_id, args.get("path", ""), args.get("data_b64", "")
            )

        self._post_result(task_id, stdout, stderr, exit_code)

    def _run_shell(self, command: str) -> tuple[str, str, int]:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.stdout[:5*1024*1024], result.stderr[:1024*1024], result.returncode
        except subprocess.TimeoutExpired:
            return "", "TIMEOUT after 300s", 1
        except Exception as e:
            return "", str(e), 1

    def _upload_file(self, task_id: str, path: str) -> tuple[str, str, int]:
        """Read local file, chunk it, send to server."""
        try:
            fpath = Path(path).expanduser()
            if not fpath.exists():
                return "", f"File not found: {path}", 1

            data  = fpath.read_bytes()
            sha   = hashlib.sha256(data).hexdigest()
            total = len(data)
            chunks = [data[i:i+CHUNK_SIZE] for i in range(0, total, CHUNK_SIZE)]

            # Init transfer
            resp = requests.post(
                f"{self.server}/api/transfer/init",
                json={
                    "direction":    "down",
                    "remote_path":  str(fpath),
                    "total_bytes":  total,
                    "sha256":       sha,
                    "total_chunks": len(chunks),
                },
                headers=self.headers,
                timeout=10,
            )
            tid = resp.json()["transfer_id"]

            # Send chunks
            for i, chunk in enumerate(chunks):
                requests.post(
                    f"{self.server}/api/transfer/chunk",
                    json={
                        "transfer_id": tid,
                        "index":       i,
                        "data_b64":    base64.b64encode(chunk).decode(),
                        "is_last":     i == len(chunks) - 1,
                    },
                    headers=self.headers,
                    timeout=30,
                )

            return f"Uploaded {path} ({total} bytes, {len(chunks)} chunks, sha256={sha[:8]})", "", 0
        except Exception as e:
            return "", str(e), 1

    def _receive_file(self, task_id: str, path: str, data_b64: str) -> tuple[str, str, int]:
        """Receive a file pushed from the operator."""
        try:
            fpath = Path(path).expanduser()
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_bytes(base64.b64decode(data_b64))
            return f"Written {path} ({fpath.stat().st_size} bytes)", "", 0
        except Exception as e:
            return "", str(e), 1

    def _post_result(self, task_id: str, stdout: str, stderr: str, exit_code: int):
        try:
            requests.post(
                f"{self.server}/api/result",
                json={
                    "task_id":   task_id,
                    "stdout":    stdout,
                    "stderr":    stderr,
                    "exit_code": exit_code,
                },
                headers=self.headers,
                timeout=30,
            )
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="TOWER C2 Agent")
    parser.add_argument("--server", default="http://100.64.0.10:8080", help="C2 server URL")
    parser.add_argument("--sleep",  type=int,   default=5,   help="Beacon interval (seconds)")
    parser.add_argument("--jitter", type=float, default=0.2, help="Jitter factor (0.0–1.0)")
    parser.add_argument("--repo",   default="", help="Git repo to track for deploys")
    args = parser.parse_args()

    agent = Agent(args.server, args.sleep, args.jitter)
    if args.repo:
        agent.tracked_repo = args.repo
    agent.run()


if __name__ == "__main__":
    main()
