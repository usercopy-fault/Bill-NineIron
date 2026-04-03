package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sbu/spectre-c2/pkg/db"
	pb "github.com/sbu/spectre-c2/pkg/proto"
	"github.com/sbu/spectre-c2/pkg/server"
)

func startTestServer(t *testing.T) (addr string, store *db.Store, cleanup func()) {
	t.Helper()
	store, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}

	srv := server.New(store)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer()
	pb.RegisterAgentServiceServer(gs, srv)
	pb.RegisterOperatorServiceServer(gs, srv)

	go gs.Serve(lis)

	return lis.Addr().String(), store, func() {
		gs.Stop()
		store.Close()
	}
}

func dialInsecure(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.Dial: %v", err)
	}
	return conn
}

// TestAgentRegistersOnConnect verifies an agent appears in the store after connecting.
func TestAgentRegistersOnConnect(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	conn := dialInsecure(t, addr)
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Send registration heartbeat
	if err := stream.Send(&pb.AgentMetrics{
		AgentId:     "test-agent-001",
		Hostname:    "kali-test",
		TailscaleIp: "100.9.9.1",
		CpuPct:      12.5,
		MemPct:      45.0,
		Timestamp:   time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) == 0 {
		t.Fatal("agent not registered in store after connect")
	}
	if agents[0].ID != "test-agent-001" {
		t.Errorf("agent ID: want test-agent-001, got %s", agents[0].ID)
	}
}

// TestAgentDisconnectUpdatesStatus verifies status goes offline on disconnect.
func TestAgentDisconnectUpdatesStatus(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	conn := dialInsecure(t, addr)
	client := pb.NewAgentServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	stream.Send(&pb.AgentMetrics{AgentId: "agent-dc-001", Hostname: "kali-dc", Timestamp: time.Now().UnixMilli()})
	time.Sleep(80 * time.Millisecond)

	// Disconnect
	stream.CloseSend()
	conn.Close()
	cancel()
	time.Sleep(100 * time.Millisecond)

	agents, _ := store.ListAgents()
	if len(agents) == 0 {
		t.Fatal("no agents in store after registration")
	}
	if agents[0].Status != "offline" {
		t.Errorf("status after disconnect: want offline, got %s", agents[0].Status)
	}
}

// TestListAgentsRPC verifies the OperatorService.ListAgents RPC.
func TestListAgentsRPC(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	// Register an agent directly in store
	store.UpsertAgent(db.Agent{
		ID:          "rpc-agent-001",
		Hostname:    "kali-rpc",
		TailscaleIP: "100.5.5.1",
		Status:      "online",
	})

	conn := dialInsecure(t, addr)
	defer conn.Close()

	opClient := pb.NewOperatorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := opClient.ListAgents(ctx, &pb.ListAgentsRequest{})
	if err != nil {
		t.Fatalf("ListAgents RPC: %v", err)
	}
	if len(resp.Agents) == 0 {
		t.Fatal("expected agents in response")
	}
}

// TestEventBusPublishSubscribe verifies events flow to subscribers.
func TestEventBusPublishSubscribe(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	conn := dialInsecure(t, addr)
	defer conn.Close()

	opClient := pb.NewOperatorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := opClient.Subscribe(ctx, &pb.SubscribeRequest{OperatorId: "op-001"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Connect an agent to trigger EVENT_AGENT_CONNECTED
	agentConn := dialInsecure(t, addr)
	defer agentConn.Close()

	agentClient := pb.NewAgentServiceClient(agentConn)
	agentStream, _ := agentClient.Connect(ctx)
	agentStream.Send(&pb.AgentMetrics{AgentId: "evt-agent-001", Hostname: "kali-evt", Timestamp: time.Now().UnixMilli()})

	// Wait for event — skip any operator-joined events first
	evtCh := make(chan *pb.Event, 4)
	go func() {
		for {
			evt, err := stream.Recv()
			if err != nil {
				return
			}
			evtCh <- evt
		}
	}()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case evt := <-evtCh:
			if evt.Type == pb.EventType_EVENT_AGENT_CONNECTED {
				if evt.AgentId != "evt-agent-001" {
					t.Errorf("event agent_id: want evt-agent-001, got %s", evt.AgentId)
				}
				return // success
			}
			// Skip other events (e.g. EVENT_OPERATOR_JOINED)
		case <-deadline:
			t.Fatal("timed out waiting for AGENT_CONNECTED event")
		}
	}
}
