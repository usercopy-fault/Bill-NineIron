#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import textwrap
import urllib.request
import difflib
import re
from typing import Dict, List, Optional, Tuple

# --- Config ---
MODEL = os.getenv("OR_MODEL", "mistralai/mistral-large")
API_KEY = os.getenv("OPENROUTER_API_KEY")
SANDBOX_ROOT = pathlib.Path(os.getenv("AGENT_SANDBOX_ROOT", os.getcwd())).resolve()
SKILLS_ROOT = pathlib.Path(os.getenv("AGENT_SKILLS_ROOT", "/home/sbu/.codex/skills"))
MAX_READ_BYTES = int(os.getenv("AGENT_MAX_READ_BYTES", "12000"))
MAX_OUTPUT = int(os.getenv("AGENT_MAX_OUTPUT", "8000"))
MCP_CONFIG = pathlib.Path(os.getenv("AGENT_MCP_CONFIG", os.path.expanduser("~/.config/agent/mcp.json")))
AUTO_TEST = os.getenv("AGENT_AUTO_TEST", "0") == "1"
TEST_CMD = os.getenv("AGENT_TEST_CMD", "")
SHELL_ALLOWLIST = os.getenv("AGENT_SHELL_ALLOWLIST", "")
SHELL_DENYLIST = os.getenv("AGENT_SHELL_DENYLIST", "")

SYSTEM = (
    "You are a terminal coding agent. "
    "Use the available tools to read/write files, list directories, run shell commands, "
    "and call MCP tools when needed. "
    "If you need to run a tool, respond ONLY with JSON like: "
    '{"tool":"read_file","path":"/abs/or/relative"}'. "
    "Never wrap tool JSON in Markdown."
)

# --- Helpers ---

def _is_within_root(path: pathlib.Path) -> bool:
    try:
        path.resolve().relative_to(SANDBOX_ROOT)
        return True
    except Exception:
        return False


def _safe_path(path_str: str) -> pathlib.Path:
    p = pathlib.Path(path_str)
    if not p.is_absolute():
        p = (SANDBOX_ROOT / p).resolve()
    else:
        p = p.resolve()
    if not _is_within_root(p):
        raise ValueError(f"Path escapes sandbox root: {p}")
    return p


def _limit(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...<truncated>..."


def _regex_match(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return False


# --- Skills ---

def _discover_skills() -> List[Tuple[str, str, str]]:
    skills = []
    if not SKILLS_ROOT.exists():
        return skills
    for skill_file in SKILLS_ROOT.glob("**/SKILL.md"):
        name = skill_file.parent.name
        desc = ""
        try:
            content = skill_file.read_text(errors="ignore")
            for line in content.splitlines():
                if line.lower().startswith("description:"):
                    desc = line.split(":", 1)[1].strip()
                    break
            if not desc:
                # Fallback to first non-empty line
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        desc = line
                        break
        except Exception:
            desc = ""
        skills.append((name, desc, str(skill_file)))
    return skills


def _skills_summary() -> str:
    skills = _discover_skills()
    if not skills:
        return "No local skills discovered."
    lines = ["Local skills (name | description | path):"]
    for name, desc, path in skills:
        lines.append(f"- {name} | {desc} | {path}")
    return "\n".join(lines)


def load_skill(path: str) -> str:
    p = _safe_path(path)
    return _limit(p.read_text(errors="ignore"), MAX_READ_BYTES)


# --- MCP (optional) ---

class MCPClient:
    def __init__(self):
        self._available = False
        self._clients = {}
        try:
            # Optional dependency. Install with: pip install mcp
            from mcp import ClientSession, StdioServerParameters  # type: ignore
            self.ClientSession = ClientSession
            self.StdioServerParameters = StdioServerParameters
            self._available = True
        except Exception:
            self._available = False

    def available(self) -> bool:
        return self._available

    def _load_config(self) -> Dict[str, Dict]:
        if not MCP_CONFIG.exists():
            return {}
        return json.loads(MCP_CONFIG.read_text())

    def _get_session(self, name: str):
        if name in self._clients:
            return self._clients[name]
        cfg = self._load_config().get(name)
        if not cfg:
            raise ValueError(f"MCP server not configured: {name}")
        command = cfg.get("command")
        args = cfg.get("args", [])
        if not command:
            raise ValueError(f"MCP server missing command: {name}")
        params = self.StdioServerParameters(command=command, args=args)
        session = self.ClientSession(params)
        self._clients[name] = session
        return session

    def list_tools(self, name: str) -> Dict:
        session = self._get_session(name)
        return session.list_tools()

    def call_tool(self, name: str, tool: str, args: Dict) -> Dict:
        session = self._get_session(name)
        return session.call_tool(tool, args)


mcp_client = MCPClient()


# --- OpenRouter ---

def call_or(messages):
    url = "https://openrouter.ai/api/v1/chat/completions"
    data = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as r:
        resp = json.loads(r.read().decode("utf-8"))
    return resp["choices"][0]["message"]["content"]


# --- Tools ---

def run_shell(cmd: str) -> str:
    if SHELL_DENYLIST and _regex_match(SHELL_DENYLIST, cmd):
        return "Blocked by AGENT_SHELL_DENYLIST"
    if SHELL_ALLOWLIST and not _regex_match(SHELL_ALLOWLIST, cmd):
        return "Blocked by AGENT_SHELL_ALLOWLIST"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        out = e.output
    return _limit(out, MAX_OUTPUT)


def read_file(path: str) -> str:
    p = _safe_path(path)
    return _limit(p.read_text(errors="ignore"), MAX_READ_BYTES)


def write_file(path: str, content: str, append: bool = False) -> str:
    p = _safe_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with p.open(mode, encoding="utf-8") as f:
        f.write(content)
    result = f"Wrote {len(content)} bytes to {p}"
    if AUTO_TEST and TEST_CMD:
        result += "\nTest output:\n" + run_shell(TEST_CMD)
    return result


def list_dir(path: str = ".") -> str:
    p = _safe_path(path)
    entries = []
    for item in sorted(p.iterdir()):
        tag = "DIR" if item.is_dir() else "FILE"
        entries.append(f"[{tag}] {item.name}")
    return "\n".join(entries)


def rg(pattern: str, path: str = ".") -> str:
    p = _safe_path(path)
    cmd = f"rg --line-number --no-heading {json.dumps(pattern)} {json.dumps(str(p))}"
    return run_shell(cmd)


def diff_file(path: str, content: str) -> str:
    p = _safe_path(path)
    old = ""
    if p.exists():
        old = p.read_text(errors="ignore")
    old_lines = old.splitlines(keepends=True)
    new_lines = content.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines, fromfile=str(p), tofile=str(p))
    return _limit("".join(diff), MAX_OUTPUT)


def run_tests() -> str:
    if not TEST_CMD:
        return "No AGENT_TEST_CMD set."
    return run_shell(TEST_CMD)


def mcp_list_tools(server: str) -> str:
    if not mcp_client.available():
        return "MCP client not available. Install with: pip install mcp"
    return json.dumps(mcp_client.list_tools(server), indent=2)


def mcp_call(server: str, tool: str, args: Dict) -> str:
    if not mcp_client.available():
        return "MCP client not available. Install with: pip install mcp"
    return json.dumps(mcp_client.call_tool(server, tool, args), indent=2)


# --- Main loop ---

def main():
    if not API_KEY:
        print("Missing OPENROUTER_API_KEY")
        sys.exit(1)

    skills_summary = _skills_summary()
    tool_help = textwrap.dedent(
        f"""
        Tools:
        - read_file: {{"tool":"read_file","path":"..."}}
        - write_file: {{"tool":"write_file","path":"...","content":"...","append":false}}
        - diff_file: {{"tool":"diff_file","path":"...","content":"..."}}
        - list_dir: {{"tool":"list_dir","path":"..."}}
        - rg: {{"tool":"rg","pattern":"...","path":"..."}}
        - shell: {{"tool":"shell","cmd":"..."}}
        - run_tests: {{"tool":"run_tests"}}
        - mcp_list_tools: {{"tool":"mcp_list_tools","server":"name"}}
        - mcp_call: {{"tool":"mcp_call","server":"name","tool":"tool_name","args":{{...}}}}

        Sandbox root: {SANDBOX_ROOT}
        Shell allowlist regex: {SHELL_ALLOWLIST or "none"}
        Shell denylist regex: {SHELL_DENYLIST or "none"}
        Auto tests: {"on" if AUTO_TEST and TEST_CMD else "off"}

        {skills_summary}
        """
    ).strip()

    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "system", "content": tool_help},
    ]

    print("Agent ready. Type your task. Ctrl+C to exit.\n")

    while True:
        user = input("you> ")
        messages.append({"role": "user", "content": user})

        while True:
            reply = call_or(messages)
            try:
                tool = json.loads(reply)
            except json.JSONDecodeError:
                print(f"agent> {reply}\n")
                messages.append({"role": "assistant", "content": reply})
                break

            name = tool.get("tool")
            try:
                if name == "shell":
                    cmd = tool.get("cmd", "")
                    print(f"[shell] {cmd}")
                    output = run_shell(cmd)
                elif name == "read_file":
                    output = read_file(tool.get("path", ""))
                elif name == "write_file":
                    output = write_file(
                        tool.get("path", ""),
                        tool.get("content", ""),
                        bool(tool.get("append", False)),
                    )
                elif name == "diff_file":
                    output = diff_file(
                        tool.get("path", ""),
                        tool.get("content", ""),
                    )
                elif name == "list_dir":
                    output = list_dir(tool.get("path", "."))
                elif name == "rg":
                    output = rg(tool.get("pattern", ""), tool.get("path", "."))
                elif name == "mcp_list_tools":
                    output = mcp_list_tools(tool.get("server", ""))
                elif name == "mcp_call":
                    output = mcp_call(
                        tool.get("server", ""),
                        tool.get("tool", ""),
                        tool.get("args", {}),
                    )
                elif name == "run_tests":
                    output = run_tests()
                else:
                    output = f"Unknown tool: {name}"
            except Exception as e:
                output = f"Tool error: {e}"

            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": f"Tool output:\n{output}"})


if __name__ == "__main__":
    main()
