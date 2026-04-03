"""TOWER C2 — GitOps Module

Integrates the C2 with the self-hosted Gitea instance.
Allows the operator to:
  - List all repos in Gitea
  - See which agents are running which commit
  - Deploy updates (git pull + restart) to one or all agents
  - Receive Gitea webhooks for auto-deploy on push

All traffic stays on the Tailscale network (100.64.0.10).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Optional

import requests

from models import Agent, GitRepo, Event, EventSeverity


GITEA_URL   = os.getenv("C2_GITEA_URL", "http://100.64.0.10:4000")
GITEA_TOKEN = os.getenv("C2_GITEA_TOKEN", "")   # set after Gitea admin setup
GITEA_USER  = os.getenv("C2_GITEA_USER", "tower-admin")
WEBHOOK_SECRET = os.getenv("C2_WEBHOOK_SECRET", "changeme-on-first-run")

# Repos managed by the tower
MANAGED_REPOS = [
    "sovereign",
    "protopilot",
    "bbhunt",
    "astronomer",
    "fingerprinter",
    "c2-agent",
]


class GitOps:
    """Gitea API wrapper + deployment logic."""

    def __init__(self, session_factory, task_queue):
        self._sf  = session_factory
        self._tq  = task_queue
        self._api = f"{GITEA_URL}/api/v1"
        self._headers = {
            "Authorization": f"token {GITEA_TOKEN}",
            "Content-Type":  "application/json",
        }

    # ── Repo Management ───────────────────────────────────────────────────────

    def list_repos(self) -> list[dict]:
        """List all repos visible to the tower admin account."""
        try:
            resp = requests.get(
                f"{self._api}/repos/search?limit=50&token={GITEA_TOKEN}",
                headers=self._headers, timeout=5,
            )
            if resp.status_code == 200:
                return resp.json().get("data", [])
        except Exception as e:
            pass
        return []

    def get_latest_commit(self, repo: str, branch: str = "main") -> Optional[str]:
        """Get the latest commit SHA for a repo/branch."""
        try:
            resp = requests.get(
                f"{self._api}/repos/{GITEA_USER}/{repo}/branches/{branch}",
                headers=self._headers, timeout=5,
            )
            if resp.status_code == 200:
                return resp.json()["commit"]["id"]
        except Exception:
            pass
        return None

    def create_repo(self, name: str, description: str = "", private: bool = True) -> bool:
        """Create a new repo in Gitea."""
        try:
            resp = requests.post(
                f"{self._api}/user/repos",
                headers=self._headers,
                json={
                    "name":        name,
                    "description": description,
                    "private":     private,
                    "auto_init":   True,
                    "default_branch": "main",
                },
                timeout=10,
            )
            return resp.status_code in (201, 409)  # 409 = already exists
        except Exception:
            return False

    def setup_webhook(self, repo: str, c2_url: str) -> bool:
        """Register C2 as a webhook receiver for push events."""
        try:
            resp = requests.post(
                f"{self._api}/repos/{GITEA_USER}/{repo}/hooks",
                headers=self._headers,
                json={
                    "type":   "gitea",
                    "active": True,
                    "events": ["push"],
                    "config": {
                        "url":          f"{c2_url}/webhook/gitea",
                        "content_type": "json",
                        "secret":       WEBHOOK_SECRET,
                    },
                },
                timeout=10,
            )
            return resp.status_code == 201
        except Exception:
            return False

    def add_team_member(self, username: str) -> dict:
        """
        Create a Gitea user account for a team member.
        Returns credentials they need to connect.
        """
        import secrets
        password = secrets.token_urlsafe(16)
        try:
            resp = requests.post(
                f"{self._api}/admin/users",
                headers=self._headers,
                json={
                    "username":             username,
                    "email":                f"{username}@tower.local",
                    "password":             password,
                    "must_change_password": True,
                    "send_email":           False,
                    "source_id":            0,
                    "login_name":           username,
                },
                timeout=10,
            )
            if resp.status_code in (201, 422):
                return {
                    "username": username,
                    "password": password,
                    "gitea_url": GITEA_URL,
                    "ssh_clone": f"git clone ssh://git@100.64.0.10:2222/{GITEA_USER}/",
                    "http_clone": f"git clone http://{username}:{password}@100.64.0.10:4000/{GITEA_USER}/",
                    "note": "Password must be changed on first login.",
                }
        except Exception as e:
            pass
        return {}

    def grant_repo_access(self, username: str, repo: str) -> bool:
        """Grant a user read access to a repo."""
        try:
            resp = requests.put(
                f"{self._api}/repos/{GITEA_USER}/{repo}/collaborators/{username}",
                headers=self._headers,
                json={"permission": "read"},
                timeout=5,
            )
            return resp.status_code in (204, 422)
        except Exception:
            return False

    # ── Deployment ────────────────────────────────────────────────────────────

    def deploy(
        self,
        repo:     str,
        agents:   list[Agent],
        branch:   str = "main",
        operator: str = "admin",
    ) -> list[str]:
        """
        Push a git pull + restart to a list of agents.
        Returns list of task IDs created.
        """
        task_ids = []
        latest = self.get_latest_commit(repo, branch)

        for agent in agents:
            task = self._tq.submit_deploy(
                agent_id = agent.id,
                repo     = repo,
                branch   = branch,
                operator = operator,
            )
            task_ids.append(task.id)

            with self._sf() as db:
                ev = Event(
                    severity = EventSeverity.INFO,
                    category = "DEPLOY",
                    message  = (
                        f"Deploy {repo}@{branch} ({(latest or 'unknown')[:8]}) "
                        f"→ {agent.hostname} [{task.id}]"
                    ),
                    agent_id = agent.id,
                    operator = operator,
                )
                db.add(ev)
                db.commit()

        return task_ids

    def deploy_all(
        self,
        repo:     str,
        branch:   str = "main",
        operator: str = "admin",
    ) -> list[str]:
        """Deploy to every active agent."""
        with self._sf() as db:
            from models import AgentStatus
            agents = db.query(Agent).filter(
                Agent.status.in_([AgentStatus.ACTIVE, AgentStatus.IDLE])
            ).all()
        return self.deploy(repo, agents, branch, operator)

    # ── Webhook Handler ───────────────────────────────────────────────────────

    def verify_webhook(self, body: bytes, signature: str) -> bool:
        """Verify Gitea HMAC-SHA256 webhook signature."""
        expected = hmac.new(
            WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature.removeprefix("sha256="))

    def handle_push(self, payload: dict, operator: str = "webhook") -> list[str]:
        """
        Called when Gitea fires a push webhook.
        Auto-deploys to all agents tracking that repo.
        """
        repo   = payload.get("repository", {}).get("name", "")
        branch = payload.get("ref", "refs/heads/main").split("/")[-1]
        pusher = payload.get("pusher", {}).get("login", "unknown")

        if not repo:
            return []

        with self._sf() as db:
            ev = Event(
                severity = EventSeverity.INFO,
                category = "WEBHOOK",
                message  = f"Push to {repo}@{branch} by {pusher} — auto-deploying",
                operator = operator,
            )
            db.add(ev)
            db.commit()

        return self.deploy_all(repo, branch, operator=f"webhook:{pusher}")

    # ── Status ────────────────────────────────────────────────────────────────

    def deployment_status(self) -> list[dict]:
        """Show which agents are running which commit of each repo."""
        repos = self.list_repos()
        status = []

        with self._sf() as db:
            agents = db.query(Agent).all()
            for repo_info in repos:
                name   = repo_info.get("name", "")
                latest = self.get_latest_commit(name)
                agents_on_repo = [
                    {
                        "agent":   a.hostname,
                        "commit":  a.git_version[:8] if a.git_version else "unknown",
                        "current": a.git_version[:8] == (latest or "")[:8],
                    }
                    for a in agents if a.git_repo == name
                ]
                status.append({
                    "repo":        name,
                    "latest":      (latest or "")[:8],
                    "agents":      agents_on_repo,
                    "needs_deploy": any(not a["current"] for a in agents_on_repo),
                })

        return status

    # ── Initial Setup ─────────────────────────────────────────────────────────

    def bootstrap(self, c2_external_url: str = f"http://100.64.0.10:8080"):
        """
        One-time bootstrap: create all managed repos and configure webhooks.
        Run after Gitea is up and admin token is set.
        """
        descriptions = {
            "sovereign":    "Bug bounty intelligence platform",
            "protopilot":   "Automated security scanner",
            "bbhunt":       "Bug bounty session launcher",
            "astronomer":   "Passive recon engine",
            "fingerprinter":"Tech stack detection",
            "c2-agent":     "C2 agent (deploy to target machines)",
        }
        results = {}
        for repo in MANAGED_REPOS:
            ok = self.create_repo(repo, descriptions.get(repo, ""), private=True)
            webhook_ok = self.setup_webhook(repo, c2_external_url) if ok else False
            results[repo] = {"created": ok, "webhook": webhook_ok}
        return results
