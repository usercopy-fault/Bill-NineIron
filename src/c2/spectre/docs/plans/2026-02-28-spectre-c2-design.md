# SPECTRE-C2: Fleet Command & Control Console — Design Document

**Date**: 2026-02-28
**Status**: Approved
**Author**: sbu
**Based on**: `compass_artifact_wf-..._text_markdown.md` + `c2expansion.zip` (SPECTRE framework)

---

## Overview

SPECTRE-C2 is a production-grade fleet operator console for a 5-8 machine Kali Linux research lab.
It provides real-time command dispatch, streaming output, distributed SPECTRE security pipeline
execution, a web dashboard, and local AI-powered finding analysis via Ollama.

This system is for authorized security research only — operated on owned lab hardware.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    OPERATOR CONSOLE (Go)                          │
│  reeflective/console + Cobra + Lip Gloss                         │
│  Fish-like syntax highlighting · Tab completion · mTLS client    │
└──────────────────────────────┬───────────────────────────────────┘
                               │  gRPC/mTLS port 7443 (protobuf)
                               │  Multiple operators supported
┌──────────────────────────────▼───────────────────────────────────┐
│                    CONTROL SERVER (Go)                            │
│  Agent registry · Task router · Event pub/sub                    │
│  SQLite state store · Web dashboard :8080 · AI analyzer          │
│  Deployed on: operator's Kali laptop (100.64.0.10)             │
└──┬─────────┬─────────┬──────────┬──────────┬────────────────────┘
   │         │         │          │          │   gRPC streaming
   ▼         ▼         ▼          ▼          ▼   (agents dial IN)
Agent-1   Agent-2   Agent-3   Agent-4   Agent-5..8
kali-01   kali-02   kali-03   kali-04   kali-N
systemd   systemd   systemd   systemd   systemd
 │         │         │          │          │
 └─────────┴────── SPECTRE subprocess tasks ──┘
          Python recon · Go scanner · Rust fuzzer
          Python exploit · Python reporting
              results stream back via gRPC → merged SQLite

       Networking: Tailscale 100.x.x.x (primary)
                   Nebula 10.99.0.x/24 (backup, self-hosted)

       AI Layer: Ollama 100.64.0.11:11434
                 deepseek-coder-v2:16b (exploit analysis)
                 qwen2.5-coder:7b (fast triage)
                 qwen2:7b (report prose)
```

---

## Component Designs

### 1. Agent (`cmd/agent/`)

- ~5MB static Go binary, deployed to each lab machine
- Configuration: `/etc/spectre-agent/agent.yaml` (server addrs, cert paths, agent-id, tags)
- Systemd service: `Restart=always`, `RestartSec=5s`
- Registers on connect: hostname, OS, CPU count, RAM, current load, tags
- Heartbeat: every 30s with live metrics (CPU%, MEM%, disk%, load avg)
- Task execution: receives `TaskRequest` → spawns subprocess → streams stdout/stderr chunks
- Fallback dial order: `tailscale-IP:7443` → `nebula-IP:7443`
- Bidirectional gRPC streaming for real-time output

### 2. Control Server (`cmd/server/`)

- gRPC server on `:7443` with mTLS (PKI managed by `cmd/certgen/`)
- HTTP server on `:8080` for web dashboard + SSE
- `AgentRegistry`: agent-id → active gRPC stream + agent metadata
- `TaskRouter`: resolves targets (`@all`, `@tag`, `name`) → fans tasks to matching agents
- `EventBus`: goroutine pub/sub — broadcasts events to operator consoles + SSE clients
- `AIAnalyzer`: goroutine pool, calls Ollama on finding completion, stores JSON in SQLite
- SQLite schema:
  - `agents(id, hostname, tailscale_ip, nebula_ip, tags, last_seen, status)`
  - `sessions(id, name, created_at, target, status)`
  - `tasks(id, session_id, type, target_agents, args, status, created_at)`
  - `task_results(id, task_id, agent_id, stdout, exit_code, duration_ms)`
  - `findings(id, session_id, agent_id, host_ip, port, severity, title, detail, cvss, ai_analysis)`
  - `events(id, type, agent_id, payload, created_at)`

### 3. Operator Console (`cmd/console/`)

- `reeflective/console` shell with multiple menus
- **`main>` menu** (fleet-wide commands):
  - `agents` — list all agents with status/metrics
  - `exec <target> <cmd...>` — run arbitrary command on target
  - `scan <target> <cidr>` — SPECTRE scan phase
  - `recon <target> <scope>` — SPECTRE recon phase
  - `fuzz <target> <ip:port>` — SPECTRE fuzzer phase
  - `exploit <target> --session <X>` — SPECTRE exploit phase
  - `report --session <X>` — generate merged report
  - `sessions` — list sessions with finding counts
  - `findings --session <X>` — query findings table
  - `triage --session <X>` — AI-ranked exploitability list
  - `analyze --session <X>` — queue AI analysis for all findings
  - `db <sql>` — raw SQLite query via console
- **`agent <name>>` menu** (per-agent context, Enter to drill in, Esc to exit)
- **Syntax highlighting** (reeflective SyntaxHighlighter callback):
  - Commands → green, flags → grey, targets → cyan, errors → red
- **Block output**: each task result is a titled bordered Lip Gloss panel
- **Transient log lines**: agent connect/disconnect events, heartbeat warnings

### 4. Web Dashboard (`internal/web/`)

- Go `net/http` + `html/template` + HTMX
- Server-Sent Events (`/events/stream`) for live agent status + task output
- Pages:
  - `/` — fleet overview grid (agent cards with CPU/MEM sparklines concept)
  - `/agents` — detailed agent list
  - `/sessions` — session history with finding counts
  - `/sessions/{id}` — session detail (findings table + task timeline)
  - `/findings` — global findings table, filterable by severity/session
  - `/findings/{id}` — finding detail with AI analysis panel

### 5. SPECTRE Task Integration

The SPECTRE binaries (`spectre_scanner`, `spectre_recon`, `spectre_fuzzer`, `spectre_exploit`,
`spectre_report`) are deployed alongside the agent binary on each lab machine.

| Console Command | SPECTRE Binary | Deployed On |
|---|---|---|
| `recon <target> <scope>` | `spectre_recon` (Python) | All agents |
| `scan <target> <cidr>` | `spectre_scanner` (Go) | All agents |
| `fuzz <target> <ip:port>` | `spectre_fuzzer` (Rust) | All agents |
| `exploit <target>` | `spectre_exploit` (Python) | All agents |
| `report --session` | Server-side only | Control server |

CIDR splitting: the server splits `10.0.0.0/24` into N equal sub-ranges, one per targeted agent.
Findings from all agents merge into one session in the server SQLite.

### 6. AI/LLM Analysis Layer

- Server-side goroutine pool (configurable concurrency, default 3)
- Triggered on `task_result` events where task type is SPECTRE_SCAN or SPECTRE_FUZZ
- Calls Ollama `/api/generate` at `100.64.0.11:11434`
- Model routing:
  - `deepseek-coder-v2:16b` → exploit analysis, CVE deep-dive (triggered by CRITICAL/HIGH)
  - `qwen2.5-coder:7b` → fast triage, severity scoring, bulk analysis (MEDIUM/LOW)
  - `qwen2:7b` → executive summary generation for reports
- AI analysis stored in `findings.ai_analysis` (JSON): exploitability, attack vectors,
  remediation, revised severity score
- Console: `finding <id> --ai` shows AI panel; `triage --session X` shows ranked list
- Report: AI analysis injected as "Analyst Commentary" block per finding

### 7. Networking

- **Primary**: Tailscale (already deployed, `100.64.0.10` for laptop)
- **Backup**: Nebula v1.10.x, subnet `10.99.0.0/24`
  - Self-hosted CA (`cmd/certgen/` also generates Nebula certs)
  - Lighthouse on cheap VPS or repurposed lab machine
  - Agents auto-failover to Nebula if Tailscale unreachable
- Both networks run simultaneously, no conflict

---

## Project Layout

```
spectre-c2/
├── cmd/
│   ├── agent/          Go: agent binary
│   ├── server/         Go: control server binary
│   ├── console/        Go: operator console binary
│   └── certgen/        Go: PKI + Nebula cert utility
├── proto/
│   └── spectre.proto   gRPC service + message definitions
├── pkg/
│   ├── agent/          agent logic (executor, heartbeat, dialer)
│   ├── server/         server logic (registry, router, eventbus)
│   ├── console/        console commands, syntax highlighter, output
│   ├── transport/      gRPC setup, mTLS, cert management
│   ├── models/         shared data types (protobuf-generated + DB)
│   ├── ai/             Ollama client, prompt templates, model router
│   └── db/             SQLite schema, migrations, queries
├── internal/
│   └── web/            HTTP handler, templates, SSE, HTMX pages
├── spectre/
│   ├── recon/          Python: DNS, OSINT, Shodan, crt.sh
│   ├── scanner/        Go: TCP/UDP scan, banner, fingerprint, checks
│   ├── fuzzer/         Rust: protocol mutation engine
│   ├── exploit/        Python: module runner, pwntools
│   └── reporting/      Python: Jinja2, WeasyPrint PDF
├── deploy/
│   ├── ansible/        Playbooks: deploy agent, install SPECTRE
│   ├── systemd/        Agent + server unit files
│   └── nebula/         Nebula config templates
├── docs/
│   └── plans/          Design docs, implementation plans
├── Makefile            build, deploy, cert-gen targets
└── go.mod
```

---

## Key Dependencies

| Layer | Library | Version |
|---|---|---|
| gRPC | `google.golang.org/grpc` | v1.62+ |
| Protobuf | `google.golang.org/protobuf` | v1.33+ |
| Console shell | `github.com/reeflective/console` | v0.1.x |
| Readline | `github.com/reeflective/readline` | v2.x |
| Commands | `github.com/spf13/cobra` | v1.8+ |
| Output styling | `github.com/charmbracelet/lipgloss` | v1.0+ |
| Database | `modernc.org/sqlite` | v1.29+ |
| Web | stdlib `net/http` + HTMX CDN | — |
| Python CLI | `typer` + `rich` | latest |
| Rust fuzzer | `tokio` + `pnet` | latest |

---

## Implementation Milestones (Report-Back Points)

1. **M1: Core gRPC Infrastructure** — agent registers, server logs it, heartbeats flow
2. **M2: Operator Console** — fish-like shell, `agents` command works, `exec` dispatches
3. **M3: SPECTRE Task Dispatch** — `scan` fans out, results stream back, SQLite populated
4. **M4: Web Dashboard** — fleet overview live at :8080, SSE streaming task output
5. **M5: AI Analysis Layer** — `analyze` command queues Ollama, findings enriched with AI

---

## Security Notes

- All gRPC communication uses mTLS: server and agents mutually authenticate via PKI
- Operator certificates issued per operator, revocable via CRL
- All operator actions logged in `events` table with attribution
- SPECTRE exploit modules require explicit `--confirmed` flag to fire
- This system is for authorized lab research only
