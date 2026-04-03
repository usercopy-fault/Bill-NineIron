package db

// schema holds all DDL statements for SPECTRE-C2's SQLite database.
// Tables: agents, sessions, tasks, task_results, findings, events,
//         defender_rules, beacon_configs, plugins.

const schemaSQL = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Agents ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL DEFAULT '',
    os           TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    cpu_cores    INTEGER NOT NULL DEFAULT 0,
    ram_bytes    INTEGER NOT NULL DEFAULT 0,
    tags         TEXT NOT NULL DEFAULT '[]',    -- JSON array
    tailscale_ip TEXT NOT NULL DEFAULT '',
    nebula_ip    TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'offline',
    last_seen    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cpu_pct      REAL NOT NULL DEFAULT 0.0,
    mem_pct      REAL NOT NULL DEFAULT 0.0,
    load_1m      REAL NOT NULL DEFAULT 0.0,
    mode         TEXT NOT NULL DEFAULT 'session'
);

-- ── Sessions ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    target     TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ── Tasks ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL DEFAULT '',
    task_type   TEXT NOT NULL DEFAULT '',
    agent_id    TEXT NOT NULL DEFAULT '',
    args        TEXT NOT NULL DEFAULT '[]',   -- JSON array
    operator_id TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- ── Task Results ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS task_results (
    task_id    TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL DEFAULT '',
    stdout     TEXT NOT NULL DEFAULT '',
    stderr     TEXT NOT NULL DEFAULT '',
    exit_code  INTEGER NOT NULL DEFAULT -1,
    completed  INTEGER NOT NULL DEFAULT 0,    -- boolean
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ── Findings ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL DEFAULT '',
    agent_id     TEXT NOT NULL DEFAULT '',
    host_ip      TEXT NOT NULL DEFAULT '',
    port         INTEGER NOT NULL DEFAULT 0,
    severity     TEXT NOT NULL DEFAULT 'info',
    title        TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    cvss_score   REAL NOT NULL DEFAULT 0.0,
    cve_refs     TEXT NOT NULL DEFAULT '[]',  -- JSON array
    raw_request  TEXT NOT NULL DEFAULT '',
    raw_response TEXT NOT NULL DEFAULT '',
    module       TEXT NOT NULL DEFAULT '',
    ai_analysis  TEXT NOT NULL DEFAULT '',    -- JSON blob from Ollama
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- ── Events ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL DEFAULT '',
    agent_id   TEXT NOT NULL DEFAULT '',
    payload    TEXT NOT NULL DEFAULT '',   -- JSON blob
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ── Defender Rules ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS defender_rules (
    id          TEXT PRIMARY KEY,
    pattern     TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    is_blocked  INTEGER NOT NULL DEFAULT 1   -- 1=block, 0=warn
);

-- ── Beacon Configs ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS beacon_configs (
    agent_id      TEXT PRIMARY KEY,
    sleep_seconds INTEGER NOT NULL DEFAULT 60,
    jitter_pct    REAL NOT NULL DEFAULT 0.1,
    kill_date     TEXT NOT NULL DEFAULT '',
    profile_name  TEXT NOT NULL DEFAULT 'default'
);

-- ── Plugins ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS plugins (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    payload     BLOB,
    loaded_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tasks_session   ON tasks(session_id);
CREATE INDEX IF NOT EXISTS idx_tasks_agent     ON tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events(type);
CREATE INDEX IF NOT EXISTS idx_agents_status   ON agents(status);
`

// seedRulesSQL inserts default Session Defender rules.
// Uses INSERT OR IGNORE so re-running migrations is idempotent.
const seedRulesSQL = `
INSERT OR IGNORE INTO defender_rules (id, pattern, description, is_blocked) VALUES
    ('rule-001', 'rm\s+-rf\s+/',        'rm -rf / is blocked',   1),
    ('rule-002', ':\(\)\{',             'fork bomb detected',     1),
    ('rule-003', '>\s*/dev/sd',         'disk wipe attempt',      1),
    ('rule-004', 'dd\s+if=/dev/zero',   'dd disk wipe',           1);
`
