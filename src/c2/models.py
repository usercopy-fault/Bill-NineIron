"""TOWER C2 — Database Models

SQLite-backed. Survives restarts. Every agent, task, transfer,
event, and recon snapshot is persisted and queryable.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, ForeignKey, JSON, create_engine,
    event as sqla_event,
)
from sqlalchemy.orm import DeclarativeBase, relationship, Session


# ── Engine ────────────────────────────────────────────────────────────────────

def make_engine(db_path: str = "data/tower.db"):
    import os; os.makedirs("data", exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    # Enable WAL mode for concurrent reads
    @sqla_event.listens_for(engine, "connect")
    def set_wal(conn, _):
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
    return engine


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class AgentStatus(str, Enum):
    ACTIVE   = "active"
    IDLE     = "idle"
    DEAD     = "dead"
    ARCHIVED = "archived"

class TaskStatus(str, Enum):
    PENDING    = "pending"
    WAITING    = "waiting"    # chain predecessor not yet complete
    DISPATCHED = "dispatched"
    RUNNING    = "running"
    COMPLETE   = "complete"
    FAILED     = "failed"
    EXPIRED    = "expired"
    CANCELLED  = "cancelled"

class TaskType(str, Enum):
    SHELL    = "shell"
    FILE_UP  = "file_upload"
    FILE_DOWN= "file_download"
    MODULE   = "module"
    DEPLOY   = "deploy"         # git pull + restart
    CHAIN    = "chain"

class TransferStatus(str, Enum):
    PENDING  = "pending"
    ACTIVE   = "active"
    COMPLETE = "complete"
    VERIFIED = "verified"
    FAILED   = "failed"

class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO  = "info"
    WARN  = "warn"
    ERROR = "error"
    CRIT  = "critical"


# ── Models ────────────────────────────────────────────────────────────────────

def _uuid() -> str:
    return str(uuid.uuid4())[:8]

def _now() -> datetime:
    return datetime.now(timezone.utc)


class Agent(Base):
    __tablename__ = "agents"

    id           = Column(String(8),  primary_key=True, default=_uuid)
    token        = Column(String(64), unique=True, nullable=False)
    hostname     = Column(String(128))
    tailscale_ip = Column(String(45))
    os           = Column(String(64))
    arch         = Column(String(32))
    kernel       = Column(String(128))
    username     = Column(String(64))
    is_root      = Column(Boolean, default=False)
    tier         = Column(Integer, default=2)   # 0=controller, 1=T1-primary, 2=T2-sub
    status       = Column(String(16), default=AgentStatus.ACTIVE)
    tags         = Column(JSON, default=list)
    notes        = Column(Text, default="")
    git_version  = Column(String(40), default="")   # current git commit hash
    git_repo     = Column(String(256), default="")  # which repo it tracks
    sleep        = Column(Integer, default=5)        # beacon interval seconds
    jitter       = Column(Float,   default=0.2)
    first_seen   = Column(DateTime, default=_now)
    last_seen    = Column(DateTime, default=_now)
    created_at   = Column(DateTime, default=_now)

    tasks     = relationship("Task",         back_populates="agent", cascade="all,delete")
    transfers = relationship("FileTransfer", back_populates="agent", cascade="all,delete")
    snapshots = relationship("ReconSnapshot",back_populates="agent", cascade="all,delete")

    def __repr__(self):
        return f"<Agent {self.id} {self.hostname} {self.tailscale_ip}>"


class Task(Base):
    __tablename__ = "tasks"

    id          = Column(String(8),  primary_key=True, default=_uuid)
    agent_id    = Column(String(8),  ForeignKey("agents.id"), nullable=False)
    type        = Column(String(16), default=TaskType.SHELL)
    status      = Column(String(16), default=TaskStatus.PENDING)
    priority    = Column(Integer, default=5)   # 1=critical, 10=background
    command     = Column(Text, nullable=False)
    args        = Column(JSON, default=dict)
    stdout      = Column(Text, default="")
    stderr      = Column(Text, default="")
    exit_code   = Column(Integer, nullable=True)
    ttl         = Column(Integer, default=300)  # seconds before expiry
    max_retries = Column(Integer, default=3)
    retry_count = Column(Integer, default=0)
    chain_next  = Column(String(8), nullable=True)  # task id to run on success
    operator    = Column(String(64), default="admin")
    created_at  = Column(DateTime, default=_now)
    dispatched_at = Column(DateTime, nullable=True)
    completed_at  = Column(DateTime, nullable=True)

    agent = relationship("Agent", back_populates="tasks")

    @property
    def is_expired(self) -> bool:
        if self.status != TaskStatus.PENDING:
            return False
        age = (datetime.now(timezone.utc) - self.created_at.replace(tzinfo=timezone.utc)).total_seconds()
        return age > self.ttl


class FileTransfer(Base):
    __tablename__ = "file_transfers"

    id          = Column(String(8),  primary_key=True, default=_uuid)
    agent_id    = Column(String(8),  ForeignKey("agents.id"), nullable=False)
    direction   = Column(String(4),  nullable=False)  # "up" or "down"
    remote_path = Column(Text, nullable=False)
    local_path  = Column(Text, nullable=True)
    status      = Column(String(16), default=TransferStatus.PENDING)
    total_bytes = Column(Integer, default=0)
    transferred = Column(Integer, default=0)
    sha256      = Column(String(64), nullable=True)
    local_sha256= Column(String(64), nullable=True)
    chunk_size  = Column(Integer, default=524288)  # 512KB
    total_chunks= Column(Integer, default=0)
    received    = Column(Integer, default=0)
    created_at  = Column(DateTime, default=_now)
    completed_at= Column(DateTime, nullable=True)

    agent  = relationship("Agent",       back_populates="transfers")
    chunks = relationship("FileChunk",   back_populates="transfer", cascade="all,delete")


class FileChunk(Base):
    __tablename__ = "file_chunks"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    transfer_id = Column(String(8), ForeignKey("file_transfers.id"), nullable=False)
    index       = Column(Integer, nullable=False)
    data_b64    = Column(Text, nullable=False)
    received_at = Column(DateTime, default=_now)

    transfer = relationship("FileTransfer", back_populates="chunks")


class ReconSnapshot(Base):
    __tablename__ = "recon_snapshots"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    agent_id    = Column(String(8), ForeignKey("agents.id"), nullable=False)
    module      = Column(String(64), nullable=False)
    data        = Column(JSON, default=dict)
    raw_output  = Column(Text, default="")
    created_at  = Column(DateTime, default=_now)

    agent = relationship("Agent", back_populates="snapshots")


class Event(Base):
    __tablename__ = "events"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    severity   = Column(String(16), default=EventSeverity.INFO)
    category   = Column(String(32))
    message    = Column(Text, nullable=False)
    agent_id   = Column(String(8), nullable=True)
    operator   = Column(String(64), nullable=True)
    extra      = Column(JSON, default=dict)
    created_at = Column(DateTime, default=_now)


class ChatMessage(Base):
    """Team chat — Tailscale-only. Accessible from console or mobile browser."""
    __tablename__ = "chat_messages"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    author     = Column(String(64), nullable=False)
    message    = Column(Text,       nullable=False)
    channel    = Column(String(64), default="general")
    created_at = Column(DateTime,   default=_now)


class GitRepo(Base):
    """Tracks repos synced from Gitea and their deployment state."""
    __tablename__ = "git_repos"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String(128), unique=True, nullable=False)
    gitea_url   = Column(Text, nullable=False)
    description = Column(Text, default="")
    last_commit = Column(String(40), default="")
    last_push   = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, default=_now)


# ── Init ──────────────────────────────────────────────────────────────────────

def init_db(engine) -> None:
    Base.metadata.create_all(engine)
