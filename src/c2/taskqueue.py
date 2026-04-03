"""TOWER C2 — Task Queue Engine

State machine: PENDING → DISPATCHED → RUNNING → COMPLETE
                                               → FAILED
                       → EXPIRED
                       → CANCELLED

Every task is DB-persisted. Server restarts don't lose the queue.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from models import Agent, Task, Event, TaskStatus, TaskType, EventSeverity, AgentStatus


MAX_OUTPUT_BYTES = 10 * 1024 * 1024   # 10MB cap
BATCH_SIZE       = 5                   # tasks dispatched per beacon
EXPIRY_INTERVAL  = 30                  # seconds between expiry sweeps


class TaskQueue:
    """Thread-safe task queue backed by SQLite."""

    def __init__(self, session_factory):
        self._sf   = session_factory
        self._lock = threading.Lock()
        self._start_expiry_thread()

    # ── Submit ────────────────────────────────────────────────────────────────

    def submit_shell(
        self,
        agent_id:  str,
        command:   str,
        priority:  int  = 5,
        ttl:       int  = 300,
        operator:  str  = "admin",
        chain_next: Optional[str] = None,
    ) -> Task:
        with self._lock, self._sf() as db:
            task = Task(
                agent_id   = agent_id,
                type       = TaskType.SHELL,
                status     = TaskStatus.PENDING,
                priority   = priority,
                command    = command,
                ttl        = ttl,
                operator   = operator,
                chain_next = chain_next,
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            self._log(db, "TASK_SUBMIT", f"[{task.id}] shell: {command[:60]}", agent_id, operator)
            db.commit()
            return task

    def submit_module(
        self,
        agent_id: str,
        module:   str,
        args:     dict = None,
        priority: int  = 5,
        operator: str  = "admin",
    ) -> Task:
        with self._lock, self._sf() as db:
            task = Task(
                agent_id = agent_id,
                type     = TaskType.MODULE,
                status   = TaskStatus.PENDING,
                priority = priority,
                command  = module,
                args     = args or {},
                operator = operator,
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            self._log(db, "TASK_SUBMIT", f"[{task.id}] module: {module}", agent_id, operator)
            db.commit()
            return task

    def submit_deploy(
        self,
        agent_id: str,
        repo:     str,
        branch:   str = "main",
        operator: str = "admin",
    ) -> Task:
        """Push a git pull + restart to an agent."""
        with self._lock, self._sf() as db:
            task = Task(
                agent_id = agent_id,
                type     = TaskType.DEPLOY,
                status   = TaskStatus.PENDING,
                priority = 1,   # deploy is always critical priority
                command  = f"git -C ~/{repo} pull origin {branch} && systemctl --user restart {repo} 2>/dev/null || true",
                args     = {"repo": repo, "branch": branch},
                ttl      = 600,
                operator = operator,
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            self._log(db, "DEPLOY", f"[{task.id}] deploy {repo}@{branch} → {agent_id}", agent_id, operator)
            db.commit()
            return task

    def submit_broadcast(
        self,
        command:  str,
        tier:     int  = None,   # None = all, 1 = T1 only, 2 = T2 only
        operator: str  = "admin",
    ) -> list[str]:
        """Send the same shell command to all (or tier-filtered) active agents."""
        with self._sf() as db:
            q = db.query(Agent).filter(
                Agent.status.in_([AgentStatus.ACTIVE, AgentStatus.IDLE])
            )
            if tier is not None:
                q = q.filter(Agent.tier == tier)
            agents = q.all()
        task_ids = []
        for agent in agents:
            task = self.submit_shell(agent.id, command, operator=operator)
            task_ids.append(task.id)
        return task_ids

    def submit_chain(
        self,
        agent_id: str,
        commands: list[str],
        operator: str = "admin",
    ) -> list[Task]:
        """Chain of shell commands — each runs only if prior succeeded."""
        with self._lock, self._sf() as db:
            tasks = []
            for cmd in reversed(commands):
                next_id = tasks[-1].id if tasks else None
                task = Task(
                    agent_id   = agent_id,
                    type       = TaskType.SHELL,
                    status     = TaskStatus.WAITING,   # activated one at a time below
                    priority   = 5,
                    command    = cmd,
                    chain_next = next_id,
                    operator   = operator,
                )
                db.add(task)
                db.flush()
                tasks.append(task)
            # Only the first command in the chain should be dispatched immediately
            tasks[-1].status = TaskStatus.PENDING
            db.commit()
            for t in tasks:
                db.refresh(t)
            self._log(db, "CHAIN_SUBMIT", f"{len(tasks)}-step chain → {agent_id}", agent_id, operator)
            db.commit()
            return list(reversed(tasks))

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def get_pending_tasks(self, agent_id: str) -> list[dict]:
        """Called on each agent beacon. Returns up to BATCH_SIZE tasks."""
        with self._lock, self._sf() as db:
            tasks = (
                db.query(Task)
                .filter(
                    Task.agent_id == agent_id,
                    Task.status   == TaskStatus.PENDING,
                )
                .order_by(Task.priority, Task.created_at)
                .limit(BATCH_SIZE)
                .all()
            )
            result = []
            for t in tasks:
                t.status       = TaskStatus.DISPATCHED
                t.dispatched_at = datetime.now(timezone.utc)
                result.append({
                    "id":      t.id,
                    "type":    t.type,
                    "command": t.command,
                    "args":    t.args,
                })
            db.commit()
            return result

    # ── Results ───────────────────────────────────────────────────────────────

    def record_result(
        self,
        task_id:   str,
        stdout:    str,
        stderr:    str,
        exit_code: int,
    ) -> Optional[Task]:
        with self._lock, self._sf() as db:
            task = db.get(Task, task_id)
            if not task:
                return None

            task.stdout       = stdout[:MAX_OUTPUT_BYTES]
            task.stderr       = stderr[:MAX_OUTPUT_BYTES]
            task.exit_code    = exit_code
            task.completed_at = datetime.now(timezone.utc)
            task.status       = TaskStatus.COMPLETE if exit_code == 0 else TaskStatus.FAILED

            sev = EventSeverity.INFO if exit_code == 0 else EventSeverity.WARN
            self._log(
                db, "TASK_RESULT",
                f"[{task_id}] exit={exit_code} stdout={len(stdout)}B",
                task.agent_id,
                severity=sev,
            )

            # Activate next task in chain if this step succeeded
            if exit_code == 0 and task.chain_next:
                next_task = db.get(Task, task.chain_next)
                if next_task and next_task.status == TaskStatus.WAITING:
                    next_task.status = TaskStatus.PENDING
                    self._log(db, "CHAIN_ADVANCE",
                              f"[{task_id}] → activating [{next_task.id}]",
                              task.agent_id, severity=EventSeverity.INFO)

            db.commit()
            return task

    def cancel(self, task_id: str, operator: str = "admin") -> bool:
        with self._lock, self._sf() as db:
            task = db.get(Task, task_id)
            if task and task.status in (TaskStatus.PENDING, TaskStatus.WAITING, TaskStatus.DISPATCHED):
                task.status = TaskStatus.CANCELLED
                self._log(db, "TASK_CANCEL", f"[{task_id}] cancelled by {operator}", task.agent_id, operator)
                db.commit()
                return True
            return False

    # ── Expiry ────────────────────────────────────────────────────────────────

    def _expire_stale(self):
        with self._sf() as db:
            tasks = db.query(Task).filter(Task.status == TaskStatus.PENDING).all()
            expired = [t for t in tasks if t.is_expired]
            for t in expired:
                t.status = TaskStatus.EXPIRED
                self._log(db, "TASK_EXPIRE", f"[{t.id}] TTL exceeded", t.agent_id, severity=EventSeverity.WARN)
            if expired:
                db.commit()

    def _start_expiry_thread(self):
        def loop():
            while True:
                time.sleep(EXPIRY_INTERVAL)
                try:
                    self._expire_stale()
                except Exception:
                    pass
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._sf() as db:
            return db.get(Task, task_id)

    def list_tasks(
        self,
        agent_id: Optional[str] = None,
        status:   Optional[str] = None,
        limit:    int = 50,
    ) -> list[Task]:
        with self._sf() as db:
            q = db.query(Task)
            if agent_id: q = q.filter(Task.agent_id == agent_id)
            if status:   q = q.filter(Task.status == status)
            return q.order_by(Task.created_at.desc()).limit(limit).all()

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(
        self,
        db:       Session,
        category: str,
        message:  str,
        agent_id: Optional[str] = None,
        operator: Optional[str] = None,
        severity: str = EventSeverity.INFO,
    ):
        ev = Event(
            severity = severity,
            category = category,
            message  = message,
            agent_id = agent_id,
            operator = operator,
        )
        db.add(ev)
