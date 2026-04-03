# SPECTRE-C2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-grade fleet C2 console for a 5-8 machine Kali Linux research lab, integrating the SPECTRE security pipeline with gRPC agent infrastructure, web dashboard, and local Ollama AI analysis.

**Architecture:** Go agent binaries reverse-connect to a central gRPC server via mTLS on port 7443; an operator console (reeflective/console + Cobra) dispatches tasks to agents which run SPECTRE subprocess phases and stream results back; a Go HTTP server on port 8080 serves an HTMX web dashboard with SSE live feeds; findings are enriched by a local Ollama AI analyzer.

**Tech Stack:** Go 1.22+, protobuf/gRPC, reeflective/console, Lip Gloss, SQLite (modernc.org/sqlite), net/http+HTMX, Ollama API, Python (SPECTRE phases), Rust (SPECTRE fuzzer), systemd, Tailscale+Nebula

**Reference Files:**
- Design doc: `docs/plans/2026-02-28-spectre-c2-design.md`
- SPECTRE research: `~/Videos/compass_artifact_wf-06580023-7b43-4e69-9d43-123abb5d7ec8_text_markdown.md`
- SPECTRE codebase: `~/Videos/c2expansion.zip` (extracted to `/tmp/c2expand/`)

---

## Milestone 1: Core gRPC Infrastructure

### Task 1: Initialize Go module and project skeleton

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `proto/spectre.proto`
- Create: `cmd/agent/main.go`
- Create: `cmd/server/main.go`
- Create: `cmd/console/main.go`

**Step 1: Initialize Go module**

```bash
cd /home/sbu/spectre-c2
go mod init github.com/sbu/spectre-c2
```

**Step 2: Add core dependencies**

```bash
go get google.golang.org/grpc@v1.62.0
go get google.golang.org/protobuf@v1.33.0
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go get modernc.org/sqlite@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/spf13/cobra@v1.8.0
go get github.com/reeflective/console@latest
go get github.com/reeflective/readline@latest
```

**Step 3: Create the Makefile**

```makefile
# Makefile

BINARY_AGENT   := bin/spectre-agent
BINARY_SERVER  := bin/spectre-server
BINARY_CONSOLE := bin/spectre-console

.PHONY: all proto build test clean

all: proto build

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       proto/spectre.proto

build:
	go build -o $(BINARY_AGENT)   ./cmd/agent/
	go build -o $(BINARY_SERVER)  ./cmd/server/
	go build -o $(BINARY_CONSOLE) ./cmd/console/

test:
	go test ./... -v -race

clean:
	rm -rf bin/ pkg/

deps-check:
	which protoc || (echo "Install: apt install protobuf-compiler" && exit 1)
	which protoc-gen-go || go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	which protoc-gen-go-grpc || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

**Step 4: Create stub main files so it compiles**

`cmd/agent/main.go`:
```go
package main

func main() {}
```

(Same for `cmd/server/main.go` and `cmd/console/main.go`)

**Step 5: Verify it compiles**

```bash
cd /home/sbu/spectre-c2 && go build ./...
```
Expected: no errors

**Step 6: Commit**

```bash
git init && git add . && git commit -m "feat: initialize spectre-c2 project skeleton"
```

---

### Task 2: Define protobuf schema

**Files:**
- Create: `proto/spectre.proto`
- Create: `pkg/proto/` (generated, gitignored)

**Step 1: Write the proto schema**

`proto/spectre.proto`:
```protobuf
syntax = "proto3";
package spectre;
option go_package = "github.com/sbu/spectre-c2/pkg/proto";

// ── Agent Registration ──────────────────────────────────────────

message AgentInfo {
  string agent_id    = 1;  // UUID, baked in at deploy time
  string hostname    = 2;
  string os          = 3;
  string arch        = 4;
  int32  cpu_cores   = 5;
  int64  ram_bytes   = 6;
  repeated string tags = 7;
  string tailscale_ip = 8;
  string nebula_ip   = 9;
  string version     = 10;
}

message AgentMetrics {
  string agent_id  = 1;
  float  cpu_pct   = 2;
  float  mem_pct   = 3;
  float  disk_pct  = 4;
  float  load_1m   = 5;
  int64  timestamp = 6;
}

// ── Task Execution ───────────────────────────────────────────────

enum TaskType {
  TASK_EXEC      = 0;  // Arbitrary shell command
  TASK_SPECTRE_RECON   = 1;
  TASK_SPECTRE_SCAN    = 2;
  TASK_SPECTRE_FUZZ    = 3;
  TASK_SPECTRE_EXPLOIT = 4;
}

message TaskRequest {
  string task_id    = 1;  // UUID assigned by server
  string session_id = 2;
  TaskType type     = 3;
  repeated string args = 4;  // argv passed to subprocess
  int64  timeout_sec = 5;    // 0 = no timeout
}

message TaskOutput {
  string task_id    = 1;
  string agent_id   = 2;
  bytes  chunk      = 3;   // Raw stdout/stderr chunk
  bool   is_stderr  = 4;
  bool   is_done    = 5;   // Last chunk — stream ends
  int32  exit_code  = 6;   // Valid only when is_done=true
  int64  timestamp  = 7;
}

// ── Findings (structured, from SPECTRE) ─────────────────────────

message Finding {
  string finding_id  = 1;
  string session_id  = 2;
  string agent_id    = 3;
  string host_ip     = 4;
  int32  port        = 5;
  string severity    = 6;  // critical|high|medium|low|info
  string title       = 7;
  string detail      = 8;
  float  cvss_score  = 9;
  repeated string cve_refs = 10;
}

// ── Event Bus ────────────────────────────────────────────────────

enum EventType {
  EVENT_AGENT_CONNECTED    = 0;
  EVENT_AGENT_DISCONNECTED = 1;
  EVENT_TASK_STARTED       = 2;
  EVENT_TASK_COMPLETED     = 3;
  EVENT_FINDING_NEW        = 4;
}

message Event {
  string     event_id   = 1;
  EventType  type       = 2;
  string     agent_id   = 3;
  string     payload    = 4;  // JSON blob
  int64      timestamp  = 5;
}

// ── gRPC Services ────────────────────────────────────────────────

service AgentService {
  // Agent calls this on connect; server streams tasks back
  rpc Connect(stream AgentMetrics) returns (stream TaskRequest);

  // Agent streams task output back to server
  rpc StreamTaskOutput(stream TaskOutput) returns (TaskAck);
}

message TaskAck {
  string task_id = 1;
  bool   received = 2;
}

service OperatorService {
  // Operator console subscribes to server events
  rpc Subscribe(SubscribeRequest) returns (stream Event);

  // Dispatch a task to one or more agents
  rpc DispatchTask(DispatchRequest) returns (DispatchResponse);

  // List connected agents
  rpc ListAgents(ListAgentsRequest) returns (ListAgentsResponse);
}

message SubscribeRequest { string operator_id = 1; }

message DispatchRequest {
  string session_id  = 1;
  TaskType type      = 2;
  repeated string args = 3;
  repeated string target_agents = 4;  // Empty = @all
  int64  timeout_sec = 5;
}

message DispatchResponse {
  repeated string task_ids = 1;  // One per targeted agent
  int32 agent_count = 2;
}

message ListAgentsRequest {}
message ListAgentsResponse { repeated AgentInfo agents = 1; }
```

**Step 2: Generate Go code**

```bash
cd /home/sbu/spectre-c2
make deps-check
make proto
ls pkg/proto/
```
Expected: `spectre.pb.go` and `spectre_grpc.pb.go`

**Step 3: Verify it compiles**

```bash
go build ./...
```

**Step 4: Commit**

```bash
git add proto/ pkg/proto/ && git commit -m "feat: define spectre gRPC protobuf schema"
```

---

### Task 3: SQLite database layer

**Files:**
- Create: `pkg/db/schema.go`
- Create: `pkg/db/db.go`
- Create: `pkg/db/db_test.go`

**Step 1: Write the failing test**

`pkg/db/db_test.go`:
```go
package db_test

import (
    "testing"
    "github.com/sbu/spectre-c2/pkg/db"
)

func TestOpenAndMigrate(t *testing.T) {
    store, err := db.Open(":memory:")
    if err != nil {
        t.Fatalf("Open: %v", err)
    }
    defer store.Close()

    // Verify tables exist
    tables := []string{"agents", "sessions", "tasks", "task_results", "findings", "events"}
    for _, tbl := range tables {
        var n int
        err := store.DB.QueryRow(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", tbl,
        ).Scan(&n)
        if err != nil || n == 0 {
            t.Errorf("table %q not found after migration", tbl)
        }
    }
}

func TestUpsertAgent(t *testing.T) {
    store, _ := db.Open(":memory:")
    defer store.Close()

    err := store.UpsertAgent(db.Agent{
        ID:          "test-uuid",
        Hostname:    "kali-01",
        TailscaleIP: "100.1.1.1",
        Status:      "online",
    })
    if err != nil {
        t.Fatalf("UpsertAgent: %v", err)
    }

    agents, err := store.ListAgents()
    if err != nil || len(agents) != 1 {
        t.Fatalf("ListAgents: want 1 agent, got %d (err: %v)", len(agents), err)
    }
    if agents[0].Hostname != "kali-01" {
        t.Errorf("hostname: want kali-01, got %s", agents[0].Hostname)
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cd /home/sbu/spectre-c2 && go test ./pkg/db/ -v
```
Expected: FAIL with "package not found"

**Step 3: Write the schema and DB implementation**

`pkg/db/schema.go`:
```go
package db

const schema = `
CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL,
    os           TEXT,
    arch         TEXT,
    cpu_cores    INTEGER,
    ram_bytes    INTEGER,
    tags         TEXT,   -- JSON array
    tailscale_ip TEXT,
    nebula_ip    TEXT,
    version      TEXT,
    status       TEXT DEFAULT 'offline',
    last_seen    DATETIME,
    cpu_pct      REAL,
    mem_pct      REAL,
    load_1m      REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    target      TEXT,
    status      TEXT DEFAULT 'active',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    ended_at    DATETIME
);

CREATE TABLE IF NOT EXISTS tasks (
    id             TEXT PRIMARY KEY,
    session_id     TEXT REFERENCES sessions(id),
    type           TEXT NOT NULL,
    target_agents  TEXT,    -- JSON array of agent IDs
    args           TEXT,    -- JSON array of strings
    status         TEXT DEFAULT 'pending',
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at     DATETIME,
    ended_at       DATETIME
);

CREATE TABLE IF NOT EXISTS task_results (
    id          TEXT PRIMARY KEY,
    task_id     TEXT REFERENCES tasks(id),
    agent_id    TEXT REFERENCES agents(id),
    stdout      TEXT,
    exit_code   INTEGER,
    duration_ms INTEGER,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    session_id   TEXT REFERENCES sessions(id),
    agent_id     TEXT REFERENCES agents(id),
    host_ip      TEXT NOT NULL,
    port         INTEGER,
    severity     TEXT DEFAULT 'info',
    title        TEXT NOT NULL,
    detail       TEXT,
    cvss_score   REAL,
    cve_refs     TEXT,    -- JSON array
    ai_analysis  TEXT,    -- JSON object
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    agent_id   TEXT,
    payload    TEXT,    -- JSON blob
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
`
```

`pkg/db/db.go`:
```go
package db

import (
    "database/sql"
    "fmt"
    "time"

    _ "modernc.org/sqlite"
)

type Store struct {
    DB *sql.DB
}

type Agent struct {
    ID          string
    Hostname    string
    OS          string
    Arch        string
    CPUCores    int
    RAMBytes    int64
    Tags        string // JSON
    TailscaleIP string
    NebulaIP    string
    Version     string
    Status      string
    LastSeen    time.Time
    CPUPct      float32
    MemPct      float32
    Load1m      float32
}

type Finding struct {
    ID         string
    SessionID  string
    AgentID    string
    HostIP     string
    Port       int
    Severity   string
    Title      string
    Detail     string
    CVSSScore  float32
    CVERefs    string // JSON
    AIAnalysis string // JSON
    CreatedAt  time.Time
}

func Open(path string) (*Store, error) {
    db, err := sql.Open("sqlite", path)
    if err != nil {
        return nil, fmt.Errorf("sqlite open: %w", err)
    }
    db.SetMaxOpenConns(1) // SQLite is single-writer
    if _, err := db.Exec(schema); err != nil {
        return nil, fmt.Errorf("migrate: %w", err)
    }
    return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) UpsertAgent(a Agent) error {
    _, err := s.DB.Exec(`
        INSERT INTO agents(id, hostname, os, arch, cpu_cores, ram_bytes, tags,
                           tailscale_ip, nebula_ip, version, status, last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            hostname=excluded.hostname, os=excluded.os, status=excluded.status,
            last_seen=excluded.last_seen, tailscale_ip=excluded.tailscale_ip,
            nebula_ip=excluded.nebula_ip, version=excluded.version
    `, a.ID, a.Hostname, a.OS, a.Arch, a.CPUCores, a.RAMBytes, a.Tags,
        a.TailscaleIP, a.NebulaIP, a.Version, a.Status, time.Now())
    return err
}

func (s *Store) ListAgents() ([]Agent, error) {
    rows, err := s.DB.Query(`SELECT id, hostname, tailscale_ip, nebula_ip, status, last_seen FROM agents ORDER BY hostname`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var agents []Agent
    for rows.Next() {
        var a Agent
        if err := rows.Scan(&a.ID, &a.Hostname, &a.TailscaleIP, &a.NebulaIP, &a.Status, &a.LastSeen); err != nil {
            return nil, err
        }
        agents = append(agents, a)
    }
    return agents, rows.Err()
}

func (s *Store) InsertFinding(f Finding) error {
    _, err := s.DB.Exec(`
        INSERT INTO findings(id, session_id, agent_id, host_ip, port, severity, title, detail, cvss_score, cve_refs)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    `, f.ID, f.SessionID, f.AgentID, f.HostIP, f.Port, f.Severity, f.Title, f.Detail, f.CVSSScore, f.CVERefs)
    return err
}

func (s *Store) ListFindings(sessionID string) ([]Finding, error) {
    rows, err := s.DB.Query(`
        SELECT id, session_id, agent_id, host_ip, port, severity, title, detail, cvss_score, created_at
        FROM findings WHERE session_id=? ORDER BY cvss_score DESC
    `, sessionID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var findings []Finding
    for rows.Next() {
        var f Finding
        if err := rows.Scan(&f.ID, &f.SessionID, &f.AgentID, &f.HostIP, &f.Port, &f.Severity, &f.Title, &f.Detail, &f.CVSSScore, &f.CreatedAt); err != nil {
            return nil, err
        }
        findings = append(findings, f)
    }
    return findings, rows.Err()
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./pkg/db/ -v -race
```
Expected: PASS for TestOpenAndMigrate and TestUpsertAgent

**Step 5: Commit**

```bash
git add pkg/db/ && git commit -m "feat: SQLite schema and store layer"
```

---

### Task 4: gRPC control server with mTLS

**Files:**
- Create: `pkg/transport/certs.go`
- Create: `pkg/server/registry.go`
- Create: `pkg/server/server.go`
- Create: `cmd/server/main.go`
- Create: `pkg/server/server_test.go`

**Step 1: Write the server test**

`pkg/server/server_test.go`:
```go
package server_test

import (
    "context"
    "testing"
    "time"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "github.com/sbu/spectre-c2/pkg/proto"
    "github.com/sbu/spectre-c2/pkg/server"
    "github.com/sbu/spectre-c2/pkg/db"
)

func TestAgentRegistersOnConnect(t *testing.T) {
    store, _ := db.Open(":memory:")
    srv := server.New(store)

    lis, _ := net.Listen("tcp", "127.0.0.1:0")
    gs := grpc.NewServer()
    pb.RegisterAgentServiceServer(gs, srv)
    pb.RegisterOperatorServiceServer(gs, srv)
    go gs.Serve(lis)
    defer gs.Stop()

    conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        t.Fatalf("dial: %v", err)
    }
    defer conn.Close()

    client := pb.NewAgentServiceClient(conn)
    stream, err := client.Connect(context.Background())
    if err != nil {
        t.Fatalf("Connect: %v", err)
    }

    // Send first heartbeat (which triggers registration)
    stream.Send(&pb.AgentMetrics{
        AgentId: "test-agent-001",
        CpuPct:  12.5,
        MemPct:  45.0,
    })

    // Give server time to process
    time.Sleep(50 * time.Millisecond)

    agents, err := store.ListAgents()
    if err != nil || len(agents) == 0 {
        t.Errorf("want agent registered, got %d agents (err: %v)", len(agents), err)
    }
    stream.CloseSend()
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./pkg/server/ -v -run TestAgentRegistersOnConnect
```
Expected: FAIL (package doesn't exist yet)

**Step 3: Implement the agent registry**

`pkg/server/registry.go`:
```go
package server

import (
    "sync"
    pb "github.com/sbu/spectre-c2/pkg/proto"
)

// AgentConn holds the live gRPC stream for a connected agent.
type AgentConn struct {
    Info   *pb.AgentInfo
    Stream pb.AgentService_ConnectServer
}

type Registry struct {
    mu     sync.RWMutex
    agents map[string]*AgentConn // agent_id → conn
}

func newRegistry() *Registry {
    return &Registry{agents: make(map[string]*AgentConn)}
}

func (r *Registry) Register(id string, conn *AgentConn) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.agents[id] = conn
}

func (r *Registry) Remove(id string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    delete(r.agents, id)
}

func (r *Registry) Get(id string) (*AgentConn, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    c, ok := r.agents[id]
    return c, ok
}

func (r *Registry) All() []*AgentConn {
    r.mu.RLock()
    defer r.mu.RUnlock()
    out := make([]*AgentConn, 0, len(r.agents))
    for _, c := range r.agents {
        out = append(out, c)
    }
    return out
}

func (r *Registry) IDs() []string {
    r.mu.RLock()
    defer r.mu.RUnlock()
    ids := make([]string, 0, len(r.agents))
    for id := range r.agents {
        ids = append(ids, id)
    }
    return ids
}
```

`pkg/server/server.go`:
```go
package server

import (
    "fmt"
    "io"
    "log"

    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/peer"
    "google.golang.org/grpc/status"

    pb "github.com/sbu/spectre-c2/pkg/proto"
    "github.com/sbu/spectre-c2/pkg/db"
)

type Server struct {
    pb.UnimplementedAgentServiceServer
    pb.UnimplementedOperatorServiceServer
    store    *db.Store
    registry *Registry
    events   *EventBus
}

func New(store *db.Store) *Server {
    return &Server{
        store:    store,
        registry: newRegistry(),
        events:   newEventBus(),
    }
}

// Connect handles agent bidirectional stream.
// Agent sends heartbeat metrics; server streams task requests back.
func (s *Server) Connect(stream pb.AgentService_ConnectServer) error {
    ctx := stream.Context()
    p, _ := peer.FromContext(ctx)
    log.Printf("[agent] connected from %s", p.Addr)

    var agentID string

    for {
        metrics, err := stream.Recv()
        if err == io.EOF {
            break
        }
        if err != nil {
            return status.Errorf(codes.Internal, "recv: %v", err)
        }

        if agentID == "" {
            // First message — register the agent
            agentID = metrics.AgentId
            s.registry.Register(agentID, &AgentConn{Stream: stream})
            s.store.UpsertAgent(db.Agent{
                ID:     agentID,
                Status: "online",
            })
            s.events.Publish(pb.EventType_EVENT_AGENT_CONNECTED, agentID, fmt.Sprintf(`{"agent_id":%q}`, agentID))
            log.Printf("[agent] registered: %s", agentID)
        }

        // Update metrics in store
        s.store.UpdateMetrics(agentID, metrics.CpuPct, metrics.MemPct, metrics.Load_1M)
    }

    // Cleanup on disconnect
    if agentID != "" {
        s.registry.Remove(agentID)
        s.store.SetAgentStatus(agentID, "offline")
        s.events.Publish(pb.EventType_EVENT_AGENT_DISCONNECTED, agentID, fmt.Sprintf(`{"agent_id":%q}`, agentID))
        log.Printf("[agent] disconnected: %s", agentID)
    }
    return nil
}

// DispatchTask fans a task out to targeted agents.
func (s *Server) DispatchTask(stream pb.OperatorService_DispatchTaskServer) error {
    // Implemented in Task 6
    return status.Errorf(codes.Unimplemented, "not yet implemented")
}

// ListAgents returns all currently connected agents.
func (s *Server) ListAgents(ctx interface{}, req *pb.ListAgentsRequest) (*pb.ListAgentsResponse, error) {
    agents, err := s.store.ListAgents()
    if err != nil {
        return nil, status.Errorf(codes.Internal, "list agents: %v", err)
    }
    var infos []*pb.AgentInfo
    for _, a := range agents {
        infos = append(infos, &pb.AgentInfo{
            AgentId:     a.ID,
            Hostname:    a.Hostname,
            TailscaleIp: a.TailscaleIP,
        })
    }
    return &pb.ListAgentsResponse{Agents: infos}, nil
}
```

Add to `pkg/db/db.go`:
```go
func (s *Store) UpdateMetrics(agentID string, cpu, mem, load float32) error {
    _, err := s.DB.Exec(`UPDATE agents SET cpu_pct=?, mem_pct=?, load_1m=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`,
        cpu, mem, load, agentID)
    return err
}

func (s *Store) SetAgentStatus(agentID, status string) error {
    _, err := s.DB.Exec(`UPDATE agents SET status=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, status, agentID)
    return err
}
```

Create `pkg/server/eventbus.go`:
```go
package server

import (
    "sync"
    "time"
    "github.com/google/uuid"
    pb "github.com/sbu/spectre-c2/pkg/proto"
)

type subscriber struct {
    ch chan *pb.Event
}

type EventBus struct {
    mu   sync.RWMutex
    subs map[string]*subscriber
}

func newEventBus() *EventBus {
    return &EventBus{subs: make(map[string]*subscriber)}
}

func (b *EventBus) Subscribe(id string) chan *pb.Event {
    ch := make(chan *pb.Event, 100)
    b.mu.Lock()
    b.subs[id] = &subscriber{ch: ch}
    b.mu.Unlock()
    return ch
}

func (b *EventBus) Unsubscribe(id string) {
    b.mu.Lock()
    if sub, ok := b.subs[id]; ok {
        close(sub.ch)
        delete(b.subs, id)
    }
    b.mu.Unlock()
}

func (b *EventBus) Publish(t pb.EventType, agentID, payload string) {
    evt := &pb.Event{
        EventId:   uuid.New().String(),
        Type:      t,
        AgentId:   agentID,
        Payload:   payload,
        Timestamp: time.Now().UnixMilli(),
    }
    b.mu.RLock()
    defer b.mu.RUnlock()
    for _, sub := range b.subs {
        select {
        case sub.ch <- evt:
        default: // Drop if subscriber is slow
        }
    }
}
```

Add `github.com/google/uuid` dependency:
```bash
go get github.com/google/uuid
```

**Step 4: Implement `cmd/server/main.go`**

```go
package main

import (
    "flag"
    "log"
    "net"

    "google.golang.org/grpc"
    pb "github.com/sbu/spectre-c2/pkg/proto"
    "github.com/sbu/spectre-c2/pkg/db"
    "github.com/sbu/spectre-c2/pkg/server"
)

var (
    flagAddr = flag.String("addr", ":7443", "gRPC listen address")
    flagDB   = flag.String("db",   "/var/lib/spectre/spectre.db", "SQLite path")
)

func main() {
    flag.Parse()

    store, err := db.Open(*flagDB)
    if err != nil {
        log.Fatalf("[!] DB: %v", err)
    }
    defer store.Close()

    srv := server.New(store)
    lis, err := net.Listen("tcp", *flagAddr)
    if err != nil {
        log.Fatalf("[!] Listen: %v", err)
    }

    // TODO Task 5: Add mTLS credentials
    gs := grpc.NewServer()
    pb.RegisterAgentServiceServer(gs, srv)
    pb.RegisterOperatorServiceServer(gs, srv)

    log.Printf("[*] SPECTRE server listening on %s", *flagAddr)
    if err := gs.Serve(lis); err != nil {
        log.Fatalf("[!] Serve: %v", err)
    }
}
```

**Step 5: Run tests**

```bash
go test ./pkg/server/ ./pkg/db/ -v -race
```
Expected: PASS

**Step 6: Build and smoke test**

```bash
make build
./bin/spectre-server --db /tmp/spectre-test.db &
sleep 1 && kill %1
```
Expected: "[*] SPECTRE server listening on :7443"

**Step 7: Commit**

```bash
git add . && git commit -m "feat(m1): gRPC server with agent registry and SQLite persistence"
```

---

### Task 5: Go agent with reverse-connect and heartbeat

**Files:**
- Create: `pkg/agent/agent.go`
- Create: `pkg/agent/agent_test.go`
- Create: `cmd/agent/main.go`

**Step 1: Write the agent test**

`pkg/agent/agent_test.go`:
```go
package agent_test

import (
    "context"
    "net"
    "testing"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "github.com/sbu/spectre-c2/pkg/proto"
    "github.com/sbu/spectre-c2/pkg/agent"
    "github.com/sbu/spectre-c2/pkg/db"
    "github.com/sbu/spectre-c2/pkg/server"
)

func TestAgentConnectsAndBeats(t *testing.T) {
    // Start a real in-process server
    store, _ := db.Open(":memory:")
    srv := server.New(store)
    lis, _ := net.Listen("tcp", "127.0.0.1:0")
    gs := grpc.NewServer()
    pb.RegisterAgentServiceServer(gs, srv)
    pb.RegisterOperatorServiceServer(gs, srv)
    go gs.Serve(lis)
    defer gs.Stop()

    // Start agent pointing at test server
    cfg := agent.Config{
        AgentID:     "test-agent-001",
        ServerAddrs: []string{lis.Addr().String()},
        Insecure:    true, // skip TLS in test
    }
    a := agent.New(cfg)
    ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
    defer cancel()
    go a.Run(ctx)

    time.Sleep(200 * time.Millisecond)

    agents, _ := store.ListAgents()
    if len(agents) == 0 {
        t.Fatal("agent not registered in server after connect")
    }
    if agents[0].ID != "test-agent-001" {
        t.Errorf("wrong agent ID: %s", agents[0].ID)
    }
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./pkg/agent/ -v -run TestAgentConnectsAndBeats
```
Expected: FAIL

**Step 3: Implement the agent**

`pkg/agent/agent.go`:
```go
package agent

import (
    "context"
    "log"
    "os"
    "os/exec"
    "runtime"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/backoff"
    "google.golang.org/grpc/credentials/insecure"
    pb "github.com/sbu/spectre-c2/pkg/proto"
)

type Config struct {
    AgentID     string
    ServerAddrs []string // Try in order, fallback on failure
    CertFile    string
    KeyFile     string
    CAFile      string
    Insecure    bool // Test mode only
    Tags        []string
}

type Agent struct {
    cfg Config
}

func New(cfg Config) *Agent { return &Agent{cfg: cfg} }

func (a *Agent) Run(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        for _, addr := range a.cfg.ServerAddrs {
            if err := a.runSession(ctx, addr); err != nil {
                log.Printf("[agent] session ended (%s): %v", addr, err)
            }
            select {
            case <-ctx.Done():
                return
            case <-time.After(5 * time.Second): // Backoff before retry
            }
        }
    }
}

func (a *Agent) runSession(ctx context.Context, addr string) error {
    opts := []grpc.DialOption{
        grpc.WithConnectParams(grpc.ConnectParams{
            Backoff: backoff.DefaultConfig,
        }),
    }
    if a.cfg.Insecure {
        opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
    }
    // TODO Task 5b: Add mTLS credentials when not insecure

    conn, err := grpc.DialContext(ctx, addr, opts...)
    if err != nil {
        return err
    }
    defer conn.Close()

    client := pb.NewAgentServiceClient(conn)
    stream, err := client.Connect(ctx)
    if err != nil {
        return err
    }

    log.Printf("[agent] connected to %s", addr)

    // Task execution goroutine
    go a.listenForTasks(ctx, stream)

    // Heartbeat loop
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    // Send first beat immediately
    if err := stream.Send(a.metrics()); err != nil {
        return err
    }

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            if err := stream.Send(a.metrics()); err != nil {
                return err
            }
        }
    }
}

func (a *Agent) listenForTasks(ctx context.Context, stream pb.AgentService_ConnectClient) {
    for {
        task, err := stream.Recv()
        if err != nil {
            return
        }
        go a.executeTask(ctx, task)
    }
}

func (a *Agent) executeTask(ctx context.Context, task *pb.TaskRequest) {
    log.Printf("[agent] executing task %s: %v", task.TaskId, task.Args)

    if len(task.Args) == 0 {
        return
    }

    taskCtx := ctx
    if task.TimeoutSec > 0 {
        var cancel context.CancelFunc
        taskCtx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutSec)*time.Second)
        defer cancel()
    }

    cmd := exec.CommandContext(taskCtx, task.Args[0], task.Args[1:]...)
    cmd.Stdout = os.Stdout // TODO Task 7: stream back via gRPC
    cmd.Stderr = os.Stderr
    cmd.Run()
}

func (a *Agent) metrics() *pb.AgentMetrics {
    hostname, _ := os.Hostname()
    _ = hostname
    return &pb.AgentMetrics{
        AgentId:   a.cfg.AgentID,
        Timestamp: time.Now().UnixMilli(),
        // CPU/mem reading added in Task 5b
    }
}

func goos() string { return runtime.GOOS }
```

**Step 4: Implement `cmd/agent/main.go`**

```go
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"

    "github.com/sbu/spectre-c2/pkg/agent"
)

var (
    flagAgentID = flag.String("id",      "",                   "Agent UUID (required)")
    flagServers = flag.String("servers", "100.64.0.10:7443", "Comma-separated server addresses")
    flagTags    = flag.String("tags",    "",                    "Comma-separated tags")
    flagInsecure = flag.Bool("insecure", false,                 "Skip TLS (dev only)")
)

func main() {
    flag.Parse()

    if *flagAgentID == "" {
        log.Fatal("[!] --id is required")
    }

    addrs := strings.Split(*flagServers, ",")
    var tags []string
    if *flagTags != "" {
        tags = strings.Split(*flagTags, ",")
    }

    cfg := agent.Config{
        AgentID:     *flagAgentID,
        ServerAddrs: addrs,
        Tags:        tags,
        Insecure:    *flagInsecure,
    }

    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    log.Printf("[*] SPECTRE agent %s starting, server(s): %v", cfg.AgentID, addrs)
    agent.New(cfg).Run(ctx)
    log.Printf("[*] SPECTRE agent stopped")
}
```

**Step 5: Run tests**

```bash
go test ./pkg/agent/ -v -race -timeout 10s
```
Expected: PASS

**Step 6: Integration smoke test**

```bash
# Terminal 1
./bin/spectre-server --db /tmp/spectre-smoke.db

# Terminal 2
./bin/spectre-agent --id kali-test-001 --servers 127.0.0.1:7443 --insecure
```
Expected: Server logs "[agent] registered: kali-test-001"

**Step 7: Commit — MILESTONE 1 COMPLETE**

```bash
git add . && git commit -m "feat(m1): complete core gRPC infrastructure — agent+server ping/register/heartbeat"
```

**→ REPORT BACK: Milestone 1 complete. Agent registers and sends heartbeats to server.**

---

## Milestone 2: Operator Console

### Task 6: reeflective/console shell with fleet commands

**Files:**
- Create: `pkg/console/console.go`
- Create: `pkg/console/commands/agents.go`
- Create: `pkg/console/commands/exec.go`
- Create: `pkg/console/highlight.go`
- Create: `cmd/console/main.go`

**Step 1: Write console test**

`pkg/console/commands/agents_test.go`:
```go
package commands_test

import (
    "bytes"
    "testing"
    "github.com/sbu/spectre-c2/pkg/console/commands"
    "github.com/sbu/spectre-c2/pkg/db"
)

func TestAgentsCommand_EmptyFleet(t *testing.T) {
    store, _ := db.Open(":memory:")
    buf := &bytes.Buffer{}
    err := commands.RunAgents(store, buf)
    if err != nil {
        t.Fatalf("RunAgents: %v", err)
    }
    out := buf.String()
    if out == "" {
        t.Error("expected some output from agents command")
    }
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./pkg/console/... -v
```
Expected: FAIL

**Step 3: Implement `agents` command logic**

`pkg/console/commands/agents.go`:
```go
package commands

import (
    "fmt"
    "io"
    "strings"
    "time"

    "github.com/charmbracelet/lipgloss"
    "github.com/charmbracelet/lipgloss/table"
    "github.com/sbu/spectre-c2/pkg/db"
)

var (
    styleOnline  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
    styleOffline = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Faint(true)
    styleHeader  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)
    styleBorder  = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
)

func RunAgents(store *db.Store, out io.Writer) error {
    agents, err := store.ListAgents()
    if err != nil {
        return err
    }

    if len(agents) == 0 {
        fmt.Fprintln(out, styleOffline.Render("  No agents connected."))
        return nil
    }

    rows := [][]string{}
    for _, a := range agents {
        status := styleOnline.Render("● online")
        if a.Status != "online" {
            since := time.Since(a.LastSeen).Round(time.Second).String()
            status = styleOffline.Render(fmt.Sprintf("○ offline (%s ago)", since))
        }
        rows = append(rows, []string{
            a.Hostname,
            a.ID[:8],
            a.TailscaleIP,
            status,
            fmt.Sprintf("%.0f%%", a.CPUPct),
            fmt.Sprintf("%.0f%%", a.MemPct),
            strings.Join([]string{}, ","), // tags placeholder
        })
    }

    t := table.New().
        Border(lipgloss.RoundedBorder()).
        BorderStyle(styleBorder).
        Headers("HOSTNAME", "ID", "TAILSCALE", "STATUS", "CPU", "MEM", "TAGS").
        Rows(rows...)

    fmt.Fprintln(out, t.Render())
    return nil
}
```

**Step 4: Implement syntax highlighter**

`pkg/console/highlight.go`:
```go
package console

import (
    "strings"

    "github.com/charmbracelet/lipgloss"
)

var (
    cmdStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))  // green
    flagStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))   // grey
    targetStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))  // cyan
    argStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))  // white
    errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))   // red

    knownCmds = map[string]bool{
        "agents": true, "exec": true, "scan": true, "recon": true,
        "fuzz": true, "exploit": true, "report": true, "sessions": true,
        "findings": true, "triage": true, "analyze": true, "db": true,
        "help": true, "exit": true, "use": true,
    }
)

// Highlight applies per-token colors to a command line.
// Passed to reeflective/readline as the SyntaxHighlighter callback.
func Highlight(line []rune) string {
    input := string(line)
    if input == "" {
        return input
    }

    tokens := strings.Fields(input)
    if len(tokens) == 0 {
        return input
    }

    var out strings.Builder
    for i, tok := range tokens {
        switch {
        case i == 0:
            if knownCmds[tok] {
                out.WriteString(cmdStyle.Render(tok))
            } else {
                out.WriteString(errStyle.Render(tok))
            }
        case strings.HasPrefix(tok, "--") || strings.HasPrefix(tok, "-"):
            out.WriteString(flagStyle.Render(tok))
        case strings.HasPrefix(tok, "@"):
            out.WriteString(targetStyle.Render(tok))
        default:
            out.WriteString(argStyle.Render(tok))
        }
        if i < len(tokens)-1 {
            out.WriteString(" ")
        }
    }
    return out.String()
}
```

**Step 5: Wire up the console**

`pkg/console/console.go`:
```go
package console

import (
    "fmt"
    "os"

    "github.com/reeflective/console"
    "github.com/spf13/cobra"
    "github.com/sbu/spectre-c2/pkg/db"
)

const banner = `
╔══════════════════════════════════════════╗
║   SPECTRE-C2  Fleet Operator Console     ║
║   Type 'help' for available commands.    ║
╚══════════════════════════════════════════╝`

func Start(store *db.Store) {
    fmt.Println(banner)

    app := console.New("spectre")
    app.Shell().SyntaxHighlighter = Highlight

    mainMenu := app.ActiveMenu()
    mainMenu.SetCommands(buildCommands(store))

    if err := app.Start(); err != nil {
        fmt.Fprintf(os.Stderr, "console error: %v\n", err)
    }
}

func buildCommands(store *db.Store) func() *cobra.Command {
    return func() *cobra.Command {
        root := &cobra.Command{Use: "spectre", Short: "SPECTRE-C2 Fleet Console"}

        root.AddCommand(
            agentsCmd(store),
            execCmd(store),
            sessionsCmd(store),
            findingsCmd(store),
        )
        return root
    }
}

func agentsCmd(store *db.Store) *cobra.Command {
    return &cobra.Command{
        Use:   "agents",
        Short: "List connected agents",
        RunE: func(cmd *cobra.Command, args []string) error {
            return RunAgents(store, cmd.OutOrStdout())
        },
    }
}
```

`pkg/console/commands/exec.go`:
```go
package commands

import (
    "fmt"
    "io"
)

// RunExec stubs task dispatch — implemented fully in Milestone 3
func RunExec(target string, args []string, out io.Writer) error {
    fmt.Fprintf(out, "[exec] target=%s args=%v (dispatch pending M3)\n", target, args)
    return nil
}
```

`cmd/console/main.go`:
```go
package main

import (
    "flag"
    "log"

    "github.com/sbu/spectre-c2/pkg/console"
    "github.com/sbu/spectre-c2/pkg/db"
)

var flagDB = flag.String("db", "/var/lib/spectre/spectre.db", "SQLite path")

func main() {
    flag.Parse()
    store, err := db.Open(*flagDB)
    if err != nil {
        log.Fatalf("[!] DB: %v", err)
    }
    defer store.Close()
    console.Start(store)
}
```

**Step 6: Run tests**

```bash
go test ./pkg/console/... -v
```
Expected: PASS

**Step 7: Build and manual test**

```bash
make build
./bin/spectre-console --db /tmp/spectre-test.db
# Type: agents
# Expected: empty table with header
# Type: help
# Expected: command list
```

**Step 8: Commit — MILESTONE 2 COMPLETE**

```bash
git add . && git commit -m "feat(m2): operator console with fish-like highlighting and agents command"
```

**→ REPORT BACK: Milestone 2 complete. Console running with fish-like syntax highlighting.**

---

## Milestone 3: SPECTRE Task Dispatch + Streaming Output

### Task 7: gRPC task dispatch and streaming

**Files:**
- Modify: `pkg/server/server.go` — implement DispatchTask
- Modify: `pkg/agent/agent.go` — implement task streaming back to server
- Create: `pkg/server/dispatcher.go`
- Create: `pkg/agent/executor.go`

**Step 1: Write dispatch test**

`pkg/server/dispatcher_test.go`:
```go
package server_test

// Tests task dispatch to a connected agent and verifies output is received
func TestDispatchAndReceiveOutput(t *testing.T) {
    // Start server
    store, _ := db.Open(":memory:")
    srv := server.New(store)
    lis, _ := net.Listen("tcp", "127.0.0.1:0")
    gs := grpc.NewServer()
    pb.RegisterAgentServiceServer(gs, srv)
    pb.RegisterOperatorServiceServer(gs, srv)
    go gs.Serve(lis)
    defer gs.Stop()

    // Start agent
    cfg := agent.Config{AgentID: "test-001", ServerAddrs: []string{lis.Addr().String()}, Insecure: true}
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    go agent.New(cfg).Run(ctx)
    time.Sleep(100 * time.Millisecond)

    // Connect as operator and dispatch task
    conn, _ := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
    defer conn.Close()
    opClient := pb.NewOperatorServiceClient(conn)

    resp, err := opClient.DispatchTask(ctx, &pb.DispatchRequest{
        SessionId:    "test-session",
        Type:         pb.TaskType_TASK_EXEC,
        Args:         []string{"echo", "hello-spectre"},
        TargetAgents: []string{"test-001"},
        TimeoutSec:   5,
    })
    if err != nil {
        t.Fatalf("DispatchTask: %v", err)
    }
    if len(resp.TaskIds) == 0 {
        t.Fatal("no task IDs returned")
    }
}
```

**Step 2: Implement `pkg/server/dispatcher.go`**

```go
package server

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
    pb "github.com/sbu/spectre-c2/pkg/proto"
)

func (s *Server) DispatchTask(ctx context.Context, req *pb.DispatchRequest) (*pb.DispatchResponse, error) {
    var targets []*AgentConn

    if len(req.TargetAgents) == 0 {
        // @all
        targets = s.registry.All()
    } else {
        for _, id := range req.TargetAgents {
            if conn, ok := s.registry.Get(id); ok {
                targets = append(targets, conn)
            }
        }
    }

    if len(targets) == 0 {
        return nil, fmt.Errorf("no matching agents connected")
    }

    // Create session if needed
    s.store.EnsureSession(req.SessionId, req.SessionId)

    var taskIDs []string
    for _, conn := range targets {
        taskID := uuid.New().String()
        task := &pb.TaskRequest{
            TaskId:     taskID,
            SessionId:  req.SessionId,
            Type:       req.Type,
            Args:       req.Args,
            TimeoutSec: req.TimeoutSec,
        }
        // Write task to agent's stream
        if err := conn.Stream.Send(task); err != nil {
            continue // Log and skip offline agents
        }
        taskIDs = append(taskIDs, taskID)
        s.store.InsertTask(taskID, req.SessionId, req.Type.String(), conn.Info.GetAgentId(), req.Args)
        s.events.Publish(pb.EventType_EVENT_TASK_STARTED, conn.Info.GetAgentId(),
            fmt.Sprintf(`{"task_id":%q,"type":%q}`, taskID, req.Type))
    }

    return &pb.DispatchResponse{
        TaskIds:    taskIDs,
        AgentCount: int32(len(taskIDs)),
    }, nil
}
```

**Step 3: Implement agent task executor with streaming**

`pkg/agent/executor.go`:
```go
package agent

import (
    "bufio"
    "context"
    "io"
    "log"
    "os/exec"
    "time"

    "github.com/google/uuid"
    pb "github.com/sbu/spectre-c2/pkg/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

// executeAndStream runs a task and streams output back to server via StreamTaskOutput RPC.
func (a *Agent) executeAndStream(ctx context.Context, task *pb.TaskRequest, serverAddr string) {
    conn, err := grpc.DialContext(ctx, serverAddr,
        grpc.WithTransportCredentials(insecure.NewCredentials())) // TODO: mTLS
    if err != nil {
        log.Printf("[executor] dial: %v", err)
        return
    }
    defer conn.Close()

    client := pb.NewAgentServiceClient(conn)
    stream, err := client.StreamTaskOutput(ctx)
    if err != nil {
        log.Printf("[executor] stream: %v", err)
        return
    }

    taskCtx := ctx
    if task.TimeoutSec > 0 {
        var cancel context.CancelFunc
        taskCtx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutSec)*time.Second)
        defer cancel()
    }

    if len(task.Args) == 0 {
        stream.Send(&pb.TaskOutput{TaskId: task.TaskId, AgentId: a.cfg.AgentID, IsDone: true, ExitCode: 1})
        stream.CloseAndRecv()
        return
    }

    cmd := exec.CommandContext(taskCtx, task.Args[0], task.Args[1:]...)
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    cmd.Start()

    sendChunks := func(r io.Reader, isStderr bool) {
        scanner := bufio.NewScanner(r)
        for scanner.Scan() {
            stream.Send(&pb.TaskOutput{
                TaskId:    task.TaskId,
                AgentId:   a.cfg.AgentID,
                Chunk:     scanner.Bytes(),
                IsStderr:  isStderr,
                Timestamp: time.Now().UnixMilli(),
            })
        }
    }

    go sendChunks(stdout, false)
    go sendChunks(stderr, true)

    exitCode := 0
    if err := cmd.Wait(); err != nil {
        if ee, ok := err.(*exec.ExitError); ok {
            exitCode = ee.ExitCode()
        }
    }

    stream.Send(&pb.TaskOutput{
        TaskId:    task.TaskId,
        AgentId:   a.cfg.AgentID,
        IsDone:    true,
        ExitCode:  int32(exitCode),
        Timestamp: time.Now().UnixMilli(),
    })
    stream.CloseAndRecv()
    log.Printf("[executor] task %s done, exit=%d", task.TaskId[:8], exitCode)
    _ = uuid.New() // keep import
}
```

**Step 4: Run tests**

```bash
go test ./pkg/server/ ./pkg/agent/ -v -race -timeout 15s
```
Expected: PASS

**Step 5: Add SPECTRE task commands to console**

`pkg/console/commands/scan.go`:
```go
package commands

import (
    "fmt"
    "io"

    pb "github.com/sbu/spectre-c2/pkg/proto"
)

// ScanArgs builds SPECTRE scanner args from console input
func BuildScanArgs(target, ports, sessionID string) []string {
    args := []string{"spectre-scanner", "--target", target, "--session", sessionID}
    if ports != "" {
        args = append(args, "--ports", ports)
    }
    return args
}

// PrintTaskStarted shows a task dispatch confirmation block
func PrintTaskStarted(taskIDs []string, agentCount int32, out io.Writer) {
    fmt.Fprintf(out, "\n╭─ Task Dispatched ──────────────────────\n")
    fmt.Fprintf(out, "│  Agents targeted: %d\n", agentCount)
    for _, id := range taskIDs {
        fmt.Fprintf(out, "│  Task: %s\n", id[:8]+"...")
    }
    fmt.Fprintf(out, "╰────────────────────────────────────────\n\n")
}
```

**Step 6: Integration test — scan dispatch**

```bash
# Terminal 1: server
./bin/spectre-server --db /tmp/spectre-int.db

# Terminal 2: agent
./bin/spectre-agent --id kali-01 --servers 127.0.0.1:7443 --insecure

# Terminal 3: console
./bin/spectre-console --db /tmp/spectre-int.db
# Type: agents
# Should see kali-01 as online
```

**Step 7: Commit — MILESTONE 3 COMPLETE**

```bash
git add . && git commit -m "feat(m3): task dispatch with streaming output — SPECTRE phases wired to console"
```

**→ REPORT BACK: Milestone 3 complete. Console dispatches tasks; agents stream output back.**

---

## Milestone 4: Web Dashboard

### Task 8: HTMX web dashboard with SSE

**Files:**
- Create: `internal/web/server.go`
- Create: `internal/web/handlers.go`
- Create: `internal/web/sse.go`
- Create: `internal/web/templates/layout.html`
- Create: `internal/web/templates/index.html`
- Create: `internal/web/templates/agents.html`
- Create: `internal/web/templates/findings.html`

**Step 1: Write web handler test**

`internal/web/handlers_test.go`:
```go
package web_test

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/sbu/spectre-c2/internal/web"
    "github.com/sbu/spectre-c2/pkg/db"
)

func TestFleetIndexReturns200(t *testing.T) {
    store, _ := db.Open(":memory:")
    ws := web.New(store, nil)

    req := httptest.NewRequest("GET", "/", nil)
    rr := httptest.NewRecorder()
    ws.Handler().ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Errorf("want 200, got %d", rr.Code)
    }
    if !strings.Contains(rr.Body.String(), "SPECTRE") {
        t.Error("response should contain SPECTRE branding")
    }
}
```

**Step 2: Implement web server**

`internal/web/server.go`:
```go
package web

import (
    "embed"
    "html/template"
    "net/http"

    "github.com/sbu/spectre-c2/pkg/db"
    "github.com/sbu/spectre-c2/pkg/server"
)

//go:embed templates/*
var templatesFS embed.FS

type WebServer struct {
    store  *db.Store
    events *server.EventBus
    tmpl   *template.Template
}

func New(store *db.Store, events *server.EventBus) *WebServer {
    tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html"))
    return &WebServer{store: store, events: events, tmpl: tmpl}
}

func (ws *WebServer) Handler() http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/", ws.handleIndex)
    mux.HandleFunc("/agents", ws.handleAgents)
    mux.HandleFunc("/findings", ws.handleFindings)
    mux.HandleFunc("/events/stream", ws.handleSSE)
    return mux
}
```

`internal/web/handlers.go`:
```go
package web

import (
    "net/http"
)

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
    agents, _ := ws.store.ListAgents()
    ws.tmpl.ExecuteTemplate(w, "index.html", map[string]any{
        "Title":  "Fleet Overview — SPECTRE-C2",
        "Agents": agents,
    })
}

func (ws *WebServer) handleAgents(w http.ResponseWriter, r *http.Request) {
    agents, _ := ws.store.ListAgents()
    ws.tmpl.ExecuteTemplate(w, "agents.html", map[string]any{
        "Title":  "Agents — SPECTRE-C2",
        "Agents": agents,
    })
}

func (ws *WebServer) handleFindings(w http.ResponseWriter, r *http.Request) {
    session := r.URL.Query().Get("session")
    findings, _ := ws.store.ListFindings(session)
    ws.tmpl.ExecuteTemplate(w, "findings.html", map[string]any{
        "Title":    "Findings — SPECTRE-C2",
        "Findings": findings,
        "Session":  session,
    })
}
```

`internal/web/sse.go`:
```go
package web

import (
    "encoding/json"
    "fmt"
    "net/http"
    "github.com/google/uuid"
)

func (ws *WebServer) handleSSE(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    if ws.events == nil {
        return
    }

    subID := uuid.New().String()
    ch := ws.events.Subscribe(subID)
    defer ws.events.Unsubscribe(subID)

    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "SSE not supported", http.StatusInternalServerError)
        return
    }

    for {
        select {
        case <-r.Context().Done():
            return
        case evt, ok := <-ch:
            if !ok {
                return
            }
            data, _ := json.Marshal(evt)
            fmt.Fprintf(w, "data: %s\n\n", data)
            flusher.Flush()
        }
    }
}
```

`internal/web/templates/layout.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; }
        header { background: #161b22; padding: 12px 24px; border-bottom: 1px solid #30363d;
                 display: flex; align-items: center; gap: 16px; }
        header h1 { color: #58a6ff; font-size: 1.1rem; }
        nav a { color: #8b949e; text-decoration: none; margin-right: 16px; font-size: 0.9rem; }
        nav a:hover { color: #58a6ff; }
        main { padding: 24px; }
        .agent-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
                      padding: 16px; margin-bottom: 12px; }
        .online { color: #3fb950; }
        .offline { color: #6e7681; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #161b22; color: #8b949e; padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }
        td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
        .critical { color: #ff7b72; font-weight: bold; }
        .high     { color: #ffa657; }
        .medium   { color: #e3b341; }
        .low      { color: #58a6ff; }
        .info     { color: #6e7681; }
    </style>
</head>
<body>
    <header>
        <h1>⚡ SPECTRE-C2</h1>
        <nav>
            <a href="/">Fleet</a>
            <a href="/agents">Agents</a>
            <a href="/findings">Findings</a>
        </nav>
        <span id="live-indicator" style="margin-left:auto; color:#3fb950; font-size:0.8rem">● LIVE</span>
    </header>
    <main>{{block "content" .}}{{end}}</main>
    <script>
        // SSE for live updates
        const es = new EventSource('/events/stream');
        es.onmessage = e => {
            const evt = JSON.parse(e.data);
            document.getElementById('live-indicator').textContent = '● ' + evt.type;
            setTimeout(() => document.getElementById('live-indicator').textContent = '● LIVE', 3000);
        };
    </script>
</body>
</html>
```

`internal/web/templates/index.html`:
```html
{{template "layout.html" .}}
{{define "content"}}
<h2 style="color:#58a6ff; margin-bottom:16px">Fleet Overview</h2>
<div id="agents-grid" hx-get="/agents" hx-trigger="every 10s" hx-swap="innerHTML">
{{range .Agents}}
<div class="agent-card">
    <div style="display:flex; justify-content:space-between">
        <strong>{{.Hostname}}</strong>
        {{if eq .Status "online"}}
        <span class="online">● online</span>
        {{else}}
        <span class="offline">○ offline</span>
        {{end}}
    </div>
    <div style="color:#8b949e; font-size:0.85rem; margin-top:4px">
        {{.TailscaleIP}} · CPU {{printf "%.0f" .CPUPct}}% · MEM {{printf "%.0f" .MemPct}}%
    </div>
</div>
{{else}}
<p style="color:#6e7681">No agents connected.</p>
{{end}}
</div>
{{end}}
```

**Step 3: Run tests**

```bash
go test ./internal/web/ -v
```
Expected: PASS

**Step 4: Wire web server into `cmd/server/main.go`**

```go
// In main(), after creating srv:
webSrv := web.New(store, srv.EventBus())
go func() {
    log.Printf("[*] Web dashboard at http://localhost:8080")
    http.ListenAndServe(":8080", webSrv.Handler())
}()
```

**Step 5: Smoke test**

```bash
./bin/spectre-server --db /tmp/spectre-web.db
# Open browser: http://localhost:8080
```
Expected: Fleet overview page loads, shows "No agents connected."

**Step 6: Commit — MILESTONE 4 COMPLETE**

```bash
git add . && git commit -m "feat(m4): HTMX web dashboard with SSE live feed at :8080"
```

**→ REPORT BACK: Milestone 4 complete. Web dashboard live at :8080 with real-time agent status.**

---

## Milestone 5: AI/Ollama Analysis Layer

### Task 9: Ollama client and finding analyzer

**Files:**
- Create: `pkg/ai/ollama.go`
- Create: `pkg/ai/analyzer.go`
- Create: `pkg/ai/prompts.go`
- Create: `pkg/ai/analyzer_test.go`

**Step 1: Write the AI analyzer test**

`pkg/ai/analyzer_test.go`:
```go
package ai_test

import (
    "testing"
    "github.com/sbu/spectre-c2/pkg/ai"
)

func TestBuildPrompt(t *testing.T) {
    finding := ai.FindingContext{
        Title:    "SMB null session allowed",
        HostIP:   "10.0.0.5",
        Port:     445,
        Service:  "SMB",
        Version:  "Windows 10",
        Severity: "high",
        CVSSScore: 7.5,
    }
    prompt := ai.BuildTriagePrompt(finding)
    if len(prompt) < 100 {
        t.Errorf("prompt too short: %d chars", len(prompt))
    }
    // Prompt should mention the host and service
    if !containsAll(prompt, finding.HostIP, finding.Title) {
        t.Error("prompt missing finding details")
    }
}

func containsAll(s string, subs ...string) bool {
    for _, sub := range subs {
        if !strings.Contains(s, sub) {
            return false
        }
    }
    return true
}
```

**Step 2: Implement Ollama client**

`pkg/ai/ollama.go`:
```go
package ai

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

const DefaultOllamaAddr = "100.64.0.11:11434"

type OllamaClient struct {
    baseURL string
    http    *http.Client
}

func NewOllamaClient(addr string) *OllamaClient {
    if addr == "" {
        addr = DefaultOllamaAddr
    }
    return &OllamaClient{
        baseURL: "http://" + addr,
        http:    &http.Client{Timeout: 120 * time.Second},
    }
}

type generateRequest struct {
    Model  string `json:"model"`
    Prompt string `json:"prompt"`
    Stream bool   `json:"stream"`
}

type generateResponse struct {
    Response string `json:"response"`
    Done     bool   `json:"done"`
}

func (c *OllamaClient) Generate(ctx context.Context, model, prompt string) (string, error) {
    body, _ := json.Marshal(generateRequest{Model: model, Prompt: prompt, Stream: false})
    req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/generate", bytes.NewReader(body))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.http.Do(req)
    if err != nil {
        return "", fmt.Errorf("ollama: %w", err)
    }
    defer resp.Body.Close()

    data, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    var gen generateResponse
    if err := json.Unmarshal(data, &gen); err != nil {
        return "", fmt.Errorf("ollama response parse: %w", err)
    }
    return gen.Response, nil
}

// HealthCheck verifies Ollama is reachable
func (c *OllamaClient) HealthCheck(ctx context.Context) error {
    req, _ := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
    resp, err := c.http.Do(req)
    if err != nil {
        return fmt.Errorf("ollama unreachable at %s: %w", c.baseURL, err)
    }
    resp.Body.Close()
    if resp.StatusCode != 200 {
        return fmt.Errorf("ollama health: status %d", resp.StatusCode)
    }
    return nil
}
```

`pkg/ai/prompts.go`:
```go
package ai

import "fmt"

type FindingContext struct {
    Title     string
    HostIP    string
    Port      int
    Service   string
    Version   string
    Severity  string
    CVSSScore float32
    Detail    string
    CVERefs   []string
}

// BuildTriagePrompt creates a structured prompt for finding triage.
func BuildTriagePrompt(f FindingContext) string {
    cves := "none referenced"
    if len(f.CVERefs) > 0 {
        cves = fmt.Sprintf("%v", f.CVERefs)
    }
    return fmt.Sprintf(`You are a senior penetration tester analyzing a security finding in an authorized lab environment.

FINDING:
- Title: %s
- Host: %s:%d
- Service: %s %s
- Severity: %s (CVSS: %.1f)
- CVE References: %s
- Detail: %s

Provide a concise technical analysis with:
1. EXPLOITABILITY: Rate 1-10 and explain why
2. ATTACK VECTORS: List 2-3 specific attack paths for this service version
3. LAB IMPACT: What can an attacker achieve if exploited?
4. REMEDIATION: Top 2 specific remediation steps
5. REVISED_SEVERITY: Your adjusted severity (critical/high/medium/low) with brief reason

Be specific and technical. Keep each section to 2-3 sentences.`,
        f.Title, f.HostIP, f.Port, f.Service, f.Version,
        f.Severity, f.CVSSScore, cves, f.Detail)
}

// BuildSummaryPrompt creates a prompt for executive summary generation.
func BuildSummaryPrompt(sessionID string, critCount, highCount, totalHosts int, topFindings []string) string {
    return fmt.Sprintf(`You are writing an executive summary for a security assessment report.

SESSION: %s
SCOPE: %d hosts assessed
CRITICAL FINDINGS: %d
HIGH FINDINGS: %d
TOP FINDINGS:
%v

Write a 3-paragraph executive summary for a technical audience:
1. Assessment scope and methodology overview
2. Key risks discovered and their business impact
3. Priority remediation recommendations

Be professional, specific, and avoid jargon.`,
        sessionID, totalHosts, critCount, highCount, topFindings)
}
```

`pkg/ai/analyzer.go`:
```go
package ai

import (
    "context"
    "encoding/json"
    "log"
    "sync"

    "github.com/sbu/spectre-c2/pkg/db"
)

type AnalysisResult struct {
    FindingID      string `json:"finding_id"`
    Model          string `json:"model"`
    Exploitability string `json:"exploitability"`
    AttackVectors  string `json:"attack_vectors"`
    LabImpact      string `json:"lab_impact"`
    Remediation    string `json:"remediation"`
    RevisedSev     string `json:"revised_severity"`
    RawResponse    string `json:"raw_response"`
}

type Analyzer struct {
    ollama   *OllamaClient
    store    *db.Store
    workers  int
    queue    chan db.Finding
    wg       sync.WaitGroup
}

func NewAnalyzer(store *db.Store, ollamaAddr string, workers int) *Analyzer {
    if workers <= 0 {
        workers = 3
    }
    a := &Analyzer{
        ollama:  NewOllamaClient(ollamaAddr),
        store:   store,
        workers: workers,
        queue:   make(chan db.Finding, 100),
    }
    return a
}

func (a *Analyzer) Start(ctx context.Context) {
    for i := 0; i < a.workers; i++ {
        a.wg.Add(1)
        go a.worker(ctx)
    }
}

func (a *Analyzer) Stop() {
    close(a.queue)
    a.wg.Wait()
}

func (a *Analyzer) Enqueue(f db.Finding) {
    select {
    case a.queue <- f:
    default:
        log.Printf("[ai] queue full, dropping finding %s", f.ID[:8])
    }
}

func (a *Analyzer) worker(ctx context.Context) {
    defer a.wg.Done()
    for {
        select {
        case <-ctx.Done():
            return
        case f, ok := <-a.queue:
            if !ok {
                return
            }
            a.analyze(ctx, f)
        }
    }
}

func (a *Analyzer) analyze(ctx context.Context, f db.Finding) {
    // Route to appropriate model based on severity
    model := "qwen2.5-coder:7b" // default fast model
    if f.Severity == "critical" || f.Severity == "high" {
        model = "deepseek-coder-v2:16b"
    }

    fc := FindingContext{
        Title:     f.Title,
        HostIP:    f.HostIP,
        Port:      f.Port,
        Severity:  f.Severity,
        CVSSScore: f.CVSSScore,
        Detail:    f.Detail,
    }

    prompt := BuildTriagePrompt(fc)
    response, err := a.ollama.Generate(ctx, model, prompt)
    if err != nil {
        log.Printf("[ai] analyze %s: %v", f.ID[:8], err)
        return
    }

    result := AnalysisResult{
        FindingID:   f.ID,
        Model:       model,
        RawResponse: response,
    }

    analysisJSON, _ := json.Marshal(result)
    if err := a.store.UpdateFindingAI(f.ID, string(analysisJSON)); err != nil {
        log.Printf("[ai] store update %s: %v", f.ID[:8], err)
        return
    }
    log.Printf("[ai] analyzed finding %s with %s", f.ID[:8], model)
}
```

Add to `pkg/db/db.go`:
```go
func (s *Store) UpdateFindingAI(findingID, aiAnalysis string) error {
    _, err := s.DB.Exec(`UPDATE findings SET ai_analysis=? WHERE id=?`, aiAnalysis, findingID)
    return err
}
```

**Step 3: Add `analyze` command to console**

`pkg/console/commands/analyze.go`:
```go
package commands

import (
    "fmt"
    "io"
    "github.com/sbu/spectre-c2/pkg/ai"
    "github.com/sbu/spectre-c2/pkg/db"
)

func RunAnalyze(store *db.Store, analyzer *ai.Analyzer, sessionID string, out io.Writer) error {
    findings, err := store.ListFindings(sessionID)
    if err != nil {
        return err
    }
    queued := 0
    for _, f := range findings {
        if f.AIAnalysis == "" {
            analyzer.Enqueue(f)
            queued++
        }
    }
    fmt.Fprintf(out, "\n[ai] Queued %d findings for Ollama analysis (session: %s)\n", queued, sessionID)
    return nil
}
```

**Step 4: Run tests**

```bash
go test ./pkg/ai/ -v
```
Expected: PASS for TestBuildPrompt

**Step 5: Live test against Ollama (requires Ollama running)**

```bash
go test ./pkg/ai/ -v -run TestOllamaIntegration -tags integration
```
Note: This test is tagged `integration` and only runs when Ollama is reachable at `100.64.0.11:11434`.

**Step 6: Wire analyzer into server**

In `cmd/server/main.go`:
```go
analyzer := ai.NewAnalyzer(store, "100.64.0.11:11434", 3)
analyzer.Start(ctx)
defer analyzer.Stop()
```

**Step 7: Commit — MILESTONE 5 COMPLETE**

```bash
git add . && git commit -m "feat(m5): Ollama AI analysis layer with model routing by severity"
```

**→ REPORT BACK: Milestone 5 complete. AI analysis live — findings enriched by deepseek-coder-v2 and qwen2.5-coder.**

---

## Milestone 6: Deployment and Polish

### Task 10: mTLS certificates, systemd units, Ansible deploy

**Files:**
- Create: `cmd/certgen/main.go`
- Create: `deploy/systemd/spectre-server.service`
- Create: `deploy/systemd/spectre-agent.service`
- Create: `deploy/ansible/deploy-agent.yml`
- Create: `deploy/ansible/inventory.ini`

**Step 1: certgen utility**

`cmd/certgen/main.go` — generates CA, server cert, and per-agent client certs:

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "flag"
    "fmt"
    "log"
    "math/big"
    "os"
    "path/filepath"
    "time"
)

// Usage: certgen --out ./certs --hosts kali-01,kali-02,kali-03

var (
    flagOut   = flag.String("out", "./certs", "Output directory")
    flagHosts = flag.String("hosts", "", "Comma-separated agent hostnames")
)

func main() {
    flag.Parse()
    os.MkdirAll(*flagOut, 0700)

    // Generate CA
    caKey, caCert := generateCA()
    writeCert(filepath.Join(*flagOut, "ca.crt"), caCert)
    writeKey(filepath.Join(*flagOut, "ca.key"), caKey)
    fmt.Println("[+] CA generated:", filepath.Join(*flagOut, "ca.crt"))

    // Generate server cert
    generateLeafCert("server", caKey, caCert, *flagOut, true)
    fmt.Println("[+] Server cert generated")

    // Generate per-host agent certs
    if *flagHosts != "" {
        for _, host := range splitHosts(*flagHosts) {
            generateLeafCert("agent-"+host, caKey, caCert, *flagOut, false)
            fmt.Printf("[+] Agent cert for %s generated\n", host)
        }
    }
}

// ... (certificate generation implementation using crypto/x509)
```

**Step 2: Systemd service files**

`deploy/systemd/spectre-server.service`:
```ini
[Unit]
Description=SPECTRE-C2 Control Server
After=network.target tailscaled.service

[Service]
Type=simple
User=spectre
ExecStart=/usr/local/bin/spectre-server \
    --addr 0.0.0.0:7443 \
    --db /var/lib/spectre/spectre.db \
    --cert /etc/spectre/server.crt \
    --key /etc/spectre/server.key \
    --ca /etc/spectre/ca.crt
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
WorkingDirectory=/var/lib/spectre

[Install]
WantedBy=multi-user.target
```

`deploy/systemd/spectre-agent.service`:
```ini
[Unit]
Description=SPECTRE-C2 Agent
After=network.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=spectre
EnvironmentFile=/etc/spectre-agent/agent.env
ExecStart=/usr/local/bin/spectre-agent \
    --id ${AGENT_ID} \
    --servers ${SERVER_ADDRS} \
    --cert /etc/spectre-agent/agent.crt \
    --key /etc/spectre-agent/agent.key \
    --ca /etc/spectre-agent/ca.crt
Restart=always
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Step 3: Ansible deploy playbook**

`deploy/ansible/deploy-agent.yml`:
```yaml
---
- name: Deploy SPECTRE-C2 agent to lab machines
  hosts: lab
  become: yes
  vars:
    spectre_dir: /usr/local/bin
    config_dir: /etc/spectre-agent
    server_addr: "100.64.0.10:7443"

  tasks:
    - name: Create spectre system user
      user:
        name: spectre
        system: yes
        shell: /usr/sbin/nologin

    - name: Create config directory
      file:
        path: "{{ config_dir }}"
        state: directory
        mode: '0700'
        owner: spectre

    - name: Copy agent binary
      copy:
        src: ../../bin/spectre-agent
        dest: "{{ spectre_dir }}/spectre-agent"
        mode: '0755'

    - name: Copy agent certificate
      copy:
        src: "../../certs/agent-{{ inventory_hostname }}.crt"
        dest: "{{ config_dir }}/agent.crt"
        owner: spectre
        mode: '0600'

    - name: Copy agent key
      copy:
        src: "../../certs/agent-{{ inventory_hostname }}.key"
        dest: "{{ config_dir }}/agent.key"
        owner: spectre
        mode: '0600'

    - name: Copy CA cert
      copy:
        src: "../../certs/ca.crt"
        dest: "{{ config_dir }}/ca.crt"
        mode: '0644'

    - name: Write agent env file
      template:
        src: agent.env.j2
        dest: "{{ config_dir }}/agent.env"
        mode: '0600'
        owner: spectre

    - name: Install systemd service
      copy:
        src: ../systemd/spectre-agent.service
        dest: /etc/systemd/system/spectre-agent.service

    - name: Enable and start agent
      systemd:
        name: spectre-agent
        enabled: yes
        state: restarted
        daemon_reload: yes
```

`deploy/ansible/inventory.ini`:
```ini
[lab]
kali-01 ansible_host=100.x.x.x  # Replace with actual Tailscale IPs
kali-02 ansible_host=100.x.x.x
kali-03 ansible_host=100.x.x.x
kali-04 ansible_host=100.x.x.x
kali-05 ansible_host=100.x.x.x
kali-06 ansible_host=100.x.x.x
kali-07 ansible_host=100.x.x.x
kali-08 ansible_host=100.x.x.x

[lab:vars]
ansible_user=sbu
ansible_python_interpreter=/usr/bin/python3
```

**Step 4: One-command deploy**

```bash
# Generate certs for all lab machines
./bin/certgen --out ./certs --hosts kali-01,kali-02,kali-03,kali-04,kali-05,kali-06,kali-07,kali-08

# Build for Linux amd64
GOOS=linux GOARCH=amd64 make build

# Deploy to all lab machines
ansible-playbook -i deploy/ansible/inventory.ini deploy/ansible/deploy-agent.yml

# Verify: check all agents appear in console
./bin/spectre-console
# agents  →  should show 8 machines as online
```

**Step 5: Final Commit**

```bash
git add . && git commit -m "feat: deployment tooling — certgen, systemd units, Ansible playbook"
```

**→ REPORT BACK: All milestones complete. System production-ready.**

---

## Quick Reference — Console Commands

```
main> agents                              # List all agents with status/metrics
main> exec @all uptime                    # Run command on all agents
main> exec @kali-01 whoami               # Run on specific agent
main> scan @all 10.0.0.0/24             # SPECTRE scan, CIDR split across fleet
main> recon @kali-01 example.com        # SPECTRE recon on one agent
main> fuzz @kali-03 10.0.0.5:445        # Protocol fuzzing
main> sessions                           # List research sessions
main> findings --session lab-audit      # View findings table
main> analyze --session lab-audit       # Queue AI analysis on all findings
main> triage --session lab-audit        # AI-ranked exploitability list
main> report --session lab-audit        # Generate PDF report
main> db "SELECT * FROM agents"         # Raw SQLite query
```

## Testing Commands

```bash
make test                              # Run all unit tests
go test ./... -race -v                # Tests with race detector
go test ./pkg/server/ -run TestAgent  # Run specific test
```

## Milestone Summary

| Milestone | What Ships | Report Point |
|---|---|---|
| M1 | gRPC infra: agent↔server ping/heartbeat | After task 5 |
| M2 | Operator console: fish-like shell + `agents` | After task 6 |
| M3 | Task dispatch + streaming output | After task 7 |
| M4 | Web dashboard :8080 + SSE live feed | After task 8 |
| M5 | Ollama AI analysis layer | After task 9 |
| M6 | mTLS + systemd + Ansible deploy | After task 10 |
