package db_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sbu/spectre-c2/pkg/db"
)

func TestOpenAndMigrate(t *testing.T) {
	store, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

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

func TestUpsertAndListAgents(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	err := store.UpsertAgent(db.Agent{
		ID:          "agent-001",
		Hostname:    "kali-01",
		TailscaleIP: "100.1.1.1",
		Status:      "online",
	})
	if err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("want 1 agent, got %d", len(agents))
	}
	if agents[0].Hostname != "kali-01" {
		t.Errorf("hostname: want kali-01, got %s", agents[0].Hostname)
	}
	if agents[0].TailscaleIP != "100.1.1.1" {
		t.Errorf("tailscale_ip: want 100.1.1.1, got %s", agents[0].TailscaleIP)
	}
}

func TestUpsertAgentUpdatesOnConflict(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	store.UpsertAgent(db.Agent{ID: "agent-001", Hostname: "kali-01", Status: "online"})
	store.UpsertAgent(db.Agent{ID: "agent-001", Hostname: "kali-01", Status: "offline"})

	agents, _ := store.ListAgents()
	if agents[0].Status != "offline" {
		t.Errorf("status should be updated to offline, got %s", agents[0].Status)
	}
}

func TestInsertAndListFindings(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	// Need a session first (FK constraint)
	store.EnsureSession("sess-001", "test-session")

	err := store.InsertFinding(db.Finding{
		ID:        "find-001",
		SessionID: "sess-001",
		AgentID:   "agent-001",
		HostIP:    "10.0.0.5",
		Port:      445,
		Severity:  "high",
		Title:     "SMB null session",
		CVSSScore: 7.5,
	})
	if err != nil {
		t.Fatalf("InsertFinding: %v", err)
	}

	findings, err := store.ListFindings("sess-001")
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].HostIP != "10.0.0.5" {
		t.Errorf("host_ip: want 10.0.0.5, got %s", findings[0].HostIP)
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity: want high, got %s", findings[0].Severity)
	}
}

func TestUpdateMetrics(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	store.UpsertAgent(db.Agent{ID: "agent-001", Hostname: "kali-01", Status: "online"})
	err := store.UpdateMetrics("agent-001", 42.5, 65.0, 1.23)
	if err != nil {
		t.Fatalf("UpdateMetrics: %v", err)
	}
	agents, _ := store.ListAgents()
	if agents[0].CPUPct < 42.4 || agents[0].CPUPct > 42.6 {
		t.Errorf("cpu_pct: want ~42.5, got %f", agents[0].CPUPct)
	}
}

func TestSetAgentStatus(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	store.UpsertAgent(db.Agent{ID: "agent-001", Hostname: "kali-01", Status: "online"})
	store.SetAgentStatus("agent-001", "offline")

	agents, _ := store.ListAgents()
	if agents[0].Status != "offline" {
		t.Errorf("want offline, got %s", agents[0].Status)
	}
}

func TestUpdateFindingAI(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	store.EnsureSession("sess-001", "test")
	store.InsertFinding(db.Finding{
		ID:        "find-001",
		SessionID: "sess-001",
		AgentID:   "agent-001",
		HostIP:    "10.0.0.1",
		Severity:  "critical",
		Title:     "EternalBlue",
	})

	aiJSON := `{"exploitability":"9","attack_vectors":"ms17-010"}`
	err := store.UpdateFindingAI("find-001", aiJSON)
	if err != nil {
		t.Fatalf("UpdateFindingAI: %v", err)
	}

	findings, _ := store.ListFindings("sess-001")
	if !strings.Contains(findings[0].AIAnalysis, "ms17-010") {
		t.Errorf("ai_analysis not updated: %s", findings[0].AIAnalysis)
	}
}

func TestInsertAndListTasks(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	store.EnsureSession("sess-001", "test")
	err := store.InsertTask("task-001", "sess-001", "TASK_EXEC", "agent-001", []string{"whoami"})
	if err != nil {
		t.Fatalf("InsertTask: %v", err)
	}

	tasks, err := store.ListTasks("sess-001")
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("want 1 task, got %d", len(tasks))
	}
	if tasks[0].ID != "task-001" {
		t.Errorf("task id: want task-001, got %s", tasks[0].ID)
	}
}

// Ensure time.Time fields don't cause scan errors
func TestAgentLastSeenIsTime(t *testing.T) {
	store, _ := db.Open(":memory:")
	defer store.Close()

	store.UpsertAgent(db.Agent{ID: "agent-001", Hostname: "kali-01", Status: "online"})
	store.UpdateMetrics("agent-001", 1.0, 1.0, 0.1)

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if agents[0].LastSeen.IsZero() {
		t.Error("last_seen should not be zero after UpdateMetrics")
	}
	_ = time.Since(agents[0].LastSeen) // should not panic
}
