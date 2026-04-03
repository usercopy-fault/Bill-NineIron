package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database connection.
// DB is exported so tests and tooling can issue ad-hoc queries.
type Store struct {
	DB *sql.DB
}

// Agent represents a registered agent in the database.
type Agent struct {
	ID          string
	Hostname    string
	OS          string
	Arch        string
	CPUCores    int
	RAMBytes    int64
	Tags        string // JSON array
	TailscaleIP string
	NebulaIP    string
	Version     string
	Status      string
	LastSeen    time.Time
	CPUPct      float32
	MemPct      float32
	Load1m      float32
	Mode        string // "session" | "beacon"
}

// Finding represents a security finding in the database.
type Finding struct {
	ID          string
	SessionID   string
	AgentID     string
	HostIP      string
	Port        int
	Severity    string
	Title       string
	Detail      string
	CVSSScore   float32
	CVERefs     string // JSON array
	RawRequest  string
	RawResponse string
	Module      string
	AIAnalysis  string // JSON
	CreatedAt   time.Time
}

// Task represents a dispatched task record.
type Task struct {
	ID         string
	SessionID  string
	TaskType   string
	AgentID    string
	Args       string // JSON array
	OperatorID string
	Status     string
	CreatedAt  time.Time
}

// DefenderRule represents a Session Defender validation rule.
type DefenderRule struct {
	ID          string
	Pattern     string
	Description string
	IsBlocked   bool
}

// Open opens (or creates) a SQLite database at path and runs schema migrations.
// Pass ":memory:" for an ephemeral in-memory database.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}

	// SQLite writes must be serialised.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.DB.Close()
}

// migrate runs all DDL statements and seeds default data idempotently.
func (s *Store) migrate() error {
	if _, err := s.DB.Exec(schemaSQL); err != nil {
		return fmt.Errorf("schema DDL: %w", err)
	}
	if _, err := s.DB.Exec(seedRulesSQL); err != nil {
		return fmt.Errorf("seed rules: %w", err)
	}
	return nil
}

// ── Agents ────────────────────────────────────────────────────────────────────

// UpsertAgent inserts or updates an agent record.
func (s *Store) UpsertAgent(a Agent) error {
	if a.Tags == "" {
		a.Tags = "[]"
	}
	if a.Status == "" {
		a.Status = "online"
	}
	if a.Mode == "" {
		a.Mode = "session"
	}
	_, err := s.DB.Exec(`
		INSERT INTO agents
		    (id, hostname, os, arch, cpu_cores, ram_bytes, tags, tailscale_ip,
		     nebula_ip, version, status, last_seen, cpu_pct, mem_pct, load_1m, mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		    hostname     = excluded.hostname,
		    os           = excluded.os,
		    arch         = excluded.arch,
		    cpu_cores    = excluded.cpu_cores,
		    ram_bytes    = excluded.ram_bytes,
		    tags         = excluded.tags,
		    tailscale_ip = excluded.tailscale_ip,
		    nebula_ip    = excluded.nebula_ip,
		    version      = excluded.version,
		    status       = excluded.status,
		    last_seen    = excluded.last_seen,
		    cpu_pct      = excluded.cpu_pct,
		    mem_pct      = excluded.mem_pct,
		    load_1m      = excluded.load_1m,
		    mode         = excluded.mode`,
		a.ID, a.Hostname, a.OS, a.Arch, a.CPUCores, a.RAMBytes,
		a.Tags, a.TailscaleIP, a.NebulaIP, a.Version, a.Status,
		time.Now().UTC().Format(time.RFC3339),
		a.CPUPct, a.MemPct, a.Load1m, a.Mode,
	)
	return err
}

// SetAgentStatus updates only the status and last_seen timestamp.
func (s *Store) SetAgentStatus(id, status string) error {
	_, err := s.DB.Exec(
		`UPDATE agents SET status=?, last_seen=? WHERE id=?`,
		status, time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}

// UpdateMetrics updates CPU, memory, and load average metrics.
func (s *Store) UpdateMetrics(id string, cpu, mem, load float32) error {
	_, err := s.DB.Exec(
		`UPDATE agents SET cpu_pct=?, mem_pct=?, load_1m=?, last_seen=? WHERE id=?`,
		cpu, mem, load, time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}

// ListAgents returns all agents ordered by most recently seen.
func (s *Store) ListAgents() ([]Agent, error) {
	rows, err := s.DB.Query(`
		SELECT id, hostname, os, arch, cpu_cores, ram_bytes, tags,
		       tailscale_ip, nebula_ip, version, status, last_seen,
		       cpu_pct, mem_pct, load_1m, mode
		FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		var lastSeen string
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.OS, &a.Arch, &a.CPUCores, &a.RAMBytes,
			&a.Tags, &a.TailscaleIP, &a.NebulaIP, &a.Version, &a.Status,
			&lastSeen, &a.CPUPct, &a.MemPct, &a.Load1m, &a.Mode,
		); err != nil {
			return nil, err
		}
		a.LastSeen = parseTime(lastSeen)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// EnsureSession creates a session record if it does not already exist.
func (s *Store) EnsureSession(id, name string) error {
	_, err := s.DB.Exec(`
		INSERT OR IGNORE INTO sessions (id, name, status, created_at)
		VALUES (?, ?, 'active', ?)`,
		id, name, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// SessionRow is a lightweight session record with aggregated counts.
type SessionRow struct {
	ID           string
	Name         string
	Target       string
	Status       string
	CreatedAt    string
	FindingCount int
	TaskCount    int
}

// GetSessions returns sessions, optionally filtered by status.
func (s *Store) GetSessions(statusFilter string) ([]SessionRow, error) {
	query := `
		SELECT s.id, s.name, s.target, s.status, s.created_at,
		       COUNT(DISTINCT f.id) AS finding_count,
		       COUNT(DISTINCT t.id) AS task_count
		FROM sessions s
		LEFT JOIN findings f ON f.session_id = s.id
		LEFT JOIN tasks    t ON t.session_id = s.id`

	var args []interface{}
	if statusFilter != "" {
		query += " WHERE s.status = ?"
		args = append(args, statusFilter)
	}
	query += " GROUP BY s.id ORDER BY s.created_at DESC"

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Target, &r.Status,
			&r.CreatedAt, &r.FindingCount, &r.TaskCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ── Tasks ─────────────────────────────────────────────────────────────────────

// InsertTask records a new task dispatch.
func (s *Store) InsertTask(taskID, sessionID, taskType, agentID string, args []string) error {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		argsJSON = []byte("[]")
	}
	_, err = s.DB.Exec(`
		INSERT OR IGNORE INTO tasks (id, session_id, task_type, agent_id, args, status, created_at)
		VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
		taskID, sessionID, taskType, agentID, string(argsJSON),
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// UpdateTaskStatus changes a task's lifecycle status.
func (s *Store) UpdateTaskStatus(taskID, status string) error {
	_, err := s.DB.Exec(`UPDATE tasks SET status=? WHERE id=?`, status, taskID)
	return err
}

// ListTasks returns all tasks for a session.
func (s *Store) ListTasks(sessionID string) ([]Task, error) {
	rows, err := s.DB.Query(`
		SELECT id, session_id, task_type, agent_id, args, operator_id, status, created_at
		FROM tasks WHERE session_id=? ORDER BY created_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		var createdAt string
		if err := rows.Scan(&t.ID, &t.SessionID, &t.TaskType, &t.AgentID,
			&t.Args, &t.OperatorID, &t.Status, &createdAt); err != nil {
			return nil, err
		}
		t.CreatedAt = parseTime(createdAt)
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// AppendTaskOutput appends a streamed output chunk to a task_result record.
func (s *Store) AppendTaskOutput(taskID, agentID string, chunk []byte, isStderr bool) error {
	text := string(chunk)
	col := "stdout"
	if isStderr {
		col = "stderr"
	}
	_, err := s.DB.Exec(fmt.Sprintf(`
		INSERT INTO task_results (task_id, agent_id, %s, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(task_id) DO UPDATE SET
		    %s = %s || excluded.%s,
		    updated_at = excluded.updated_at`, col, col, col, col),
		taskID, agentID, text, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// FinalizeTaskResult marks a task result as complete with exit code.
func (s *Store) FinalizeTaskResult(taskID string, exitCode int) error {
	_, err := s.DB.Exec(`
		UPDATE task_results SET exit_code=?, completed=1, updated_at=? WHERE task_id=?`,
		exitCode, time.Now().UTC().Format(time.RFC3339), taskID,
	)
	return err
}

// ── Findings ──────────────────────────────────────────────────────────────────

// InsertFinding stores a new finding. ID is auto-generated if empty.
func (s *Store) InsertFinding(f Finding) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	if f.CVERefs == "" {
		f.CVERefs = "[]"
	}
	_, err := s.DB.Exec(`
		INSERT OR IGNORE INTO findings
		    (id, session_id, agent_id, host_ip, port, severity, title, detail,
		     cvss_score, cve_refs, raw_request, raw_response, module, ai_analysis, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.SessionID, f.AgentID, f.HostIP, f.Port, f.Severity, f.Title, f.Detail,
		f.CVSSScore, f.CVERefs, f.RawRequest, f.RawResponse, f.Module, f.AIAnalysis,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// UpdateFindingAI stores AI-generated analysis JSON for a finding.
func (s *Store) UpdateFindingAI(findingID, jsonData string) error {
	_, err := s.DB.Exec(`UPDATE findings SET ai_analysis=? WHERE id=?`, jsonData, findingID)
	return err
}

// ListFindings returns all findings for a session ordered by CVSS score descending.
func (s *Store) ListFindings(sessionID string) ([]Finding, error) {
	return s.queryFindings(sessionID, "")
}

// ListFindingsBySeverity returns findings filtered by severity.
func (s *Store) ListFindingsBySeverity(sessionID, severity string) ([]Finding, error) {
	return s.queryFindings(sessionID, severity)
}

func (s *Store) queryFindings(sessionID, severity string) ([]Finding, error) {
	query := `
		SELECT id, session_id, agent_id, host_ip, port, severity, title, detail,
		       cvss_score, cve_refs, raw_request, raw_response, module, ai_analysis, created_at
		FROM findings WHERE 1=1`
	var args []interface{}

	if sessionID != "" {
		query += " AND session_id = ?"
		args = append(args, sessionID)
	}
	if severity != "" {
		query += " AND severity = ?"
		args = append(args, strings.ToLower(severity))
	}
	query += " ORDER BY cvss_score DESC, created_at DESC"

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var createdAt string
		if err := rows.Scan(
			&f.ID, &f.SessionID, &f.AgentID, &f.HostIP, &f.Port,
			&f.Severity, &f.Title, &f.Detail, &f.CVSSScore, &f.CVERefs,
			&f.RawRequest, &f.RawResponse, &f.Module, &f.AIAnalysis, &createdAt,
		); err != nil {
			return nil, err
		}
		f.CreatedAt = parseTime(createdAt)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// ── Events ────────────────────────────────────────────────────────────────────

// InsertEvent stores an event record.
func (s *Store) InsertEvent(eventType, agentID, payload string) error {
	_, err := s.DB.Exec(`
		INSERT INTO events (id, type, agent_id, payload, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		uuid.New().String(), eventType, agentID, payload,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// ── Defender Rules ────────────────────────────────────────────────────────────

// GetDefenderRules returns all Session Defender rules ordered by ID.
func (s *Store) GetDefenderRules() ([]DefenderRule, error) {
	rows, err := s.DB.Query(`SELECT id, pattern, description, is_blocked FROM defender_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DefenderRule
	for rows.Next() {
		var r DefenderRule
		var isBlocked int
		if err := rows.Scan(&r.ID, &r.Pattern, &r.Description, &isBlocked); err != nil {
			return nil, err
		}
		r.IsBlocked = isBlocked != 0
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseTime tries RFC3339 then SQLite datetime format.
func parseTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return t
	}
	return time.Time{}
}
