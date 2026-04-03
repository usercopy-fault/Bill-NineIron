package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbu/spectre-c2/pkg/db"
	pb "github.com/sbu/spectre-c2/pkg/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements both AgentService and OperatorService.
type Server struct {
	pb.UnimplementedAgentServiceServer
	pb.UnimplementedOperatorServiceServer

	store    *db.Store
	registry *Registry
	bus      *EventBus
	defender *Defender
}

// New constructs a Server with a database store.
func New(store *db.Store) *Server {
	return &Server{
		store:    store,
		registry: NewRegistry(),
		bus:      NewEventBus(),
		defender: NewDefender(store),
	}
}

// ── AgentService ──────────────────────────────────────────────────────────────

// Connect handles SESSION-mode agents. The agent opens a bidirectional stream:
//   - Inbound (agent → server): AgentMetrics heartbeats
//   - Outbound (server → agent): TaskRequests
//
// The first received message is treated as registration.
func (s *Server) Connect(stream pb.AgentService_ConnectServer) error {
	// First message carries registration info.
	metrics, err := stream.Recv()
	if err != nil {
		return err
	}

	agentID := metrics.AgentId
	hostname := metrics.AgentName
	if agentID == "" {
		return status.Error(codes.InvalidArgument, "agent_id is required in first metrics message")
	}

	// Build agent record.
	a := db.Agent{
		ID:       agentID,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Status:   "online",
		Mode:     "session",
		CPUPct:   metrics.CpuPct,
		MemPct:   metrics.MemPct,
		Load1m:   metrics.Load_1M,
	}
	if err := s.store.UpsertAgent(a); err != nil {
		log.Printf("[agent] upsert %s: %v", agentID, err)
	}

	info := &pb.AgentInfo{
		AgentId:  agentID,
		Hostname: hostname,
		Mode:     pb.AgentMode_AGENT_MODE_SESSION,
	}
	conn := &AgentConn{
		Info:   info,
		Stream: stream,
		Mode:   pb.AgentMode_AGENT_MODE_SESSION,
	}
	s.registry.Register(agentID, conn)
	defer func() {
		s.registry.Remove(agentID)
		if setErr := s.store.SetAgentStatus(agentID, "offline"); setErr != nil {
			log.Printf("[agent] set offline %s: %v", agentID, setErr)
		}
		s.bus.Publish(pb.EventType_EVENT_AGENT_DISCONNECTED, agentID, "", `{}`)
		log.Printf("[agent] disconnected: %s", agentID)
	}()

	log.Printf("[agent] registered: %s (hostname=%s mode=session)", agentID, hostname)
	s.bus.Publish(pb.EventType_EVENT_AGENT_CONNECTED, agentID, "",
		fmt.Sprintf(`{"agent_id":%q,"hostname":%q}`, agentID, hostname))

	// Main loop: receive heartbeat metrics, update DB.
	// Task dispatch happens via stream.Send() called from DispatchTask.
	for {
		m, recvErr := stream.Recv()
		if recvErr == io.EOF {
			return nil
		}
		if recvErr != nil {
			return recvErr
		}
		if dbErr := s.store.UpdateMetrics(agentID, m.CpuPct, m.MemPct, m.Load_1M); dbErr != nil {
			log.Printf("[agent] update metrics %s: %v", agentID, dbErr)
		}
	}
}

// StreamTaskOutput receives streaming task output chunks from an agent and
// persists them.  When is_done is true the task is finalised and an event is
// published.  If out_type==OUTPUT_FINDING the structured JSON is parsed as a
// Finding and inserted into the database.
func (s *Server) StreamTaskOutput(stream pb.AgentService_StreamTaskOutputServer) error {
	var lastTaskID string
	var lastAgentID string

	for {
		out, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		lastTaskID = out.TaskId
		lastAgentID = out.AgentId

		// Persist the chunk.
		if len(out.Chunk) > 0 {
			if dbErr := s.store.AppendTaskOutput(out.TaskId, out.AgentId, out.Chunk, out.IsStderr); dbErr != nil {
				log.Printf("[output] append %s: %v", out.TaskId, dbErr)
			}
		}

		if out.IsDone {
			// Finalise task result.
			if dbErr := s.store.FinalizeTaskResult(out.TaskId, int(out.ExitCode)); dbErr != nil {
				log.Printf("[output] finalize %s: %v", out.TaskId, dbErr)
			}
			if dbErr := s.store.UpdateTaskStatus(out.TaskId, "done"); dbErr != nil {
				log.Printf("[output] task status %s: %v", out.TaskId, dbErr)
			}
			s.bus.Publish(pb.EventType_EVENT_TASK_COMPLETED, out.AgentId, "",
				fmt.Sprintf(`{"task_id":%q,"exit_code":%d}`, out.TaskId, out.ExitCode))

			// Handle structured output.
			if out.OutType == pb.TaskOutputType_OUTPUT_FINDING && out.Structured != "" {
				s.handleFindingOutput(out)
			}
		}
	}

	ack := &pb.TaskAck{Received: true}
	if lastTaskID != "" {
		ack.TaskId = lastTaskID
	}
	_ = lastAgentID
	return stream.Send(ack)
}

// handleFindingOutput parses structured JSON from a TaskOutput and inserts a
// Finding into the database.
func (s *Server) handleFindingOutput(out *pb.TaskOutput) {
	var proto pb.Finding
	if err := json.Unmarshal([]byte(out.Structured), &proto); err != nil {
		log.Printf("[output] parse finding JSON for task %s: %v", out.TaskId, err)
		return
	}

	cveJSON, _ := json.Marshal(proto.CveRefs)
	f := db.Finding{
		ID:          proto.FindingId,
		SessionID:   proto.SessionId,
		AgentID:     out.AgentId,
		HostIP:      proto.HostIp,
		Port:        int(proto.Port),
		Severity:    proto.Severity,
		Title:       proto.Title,
		Detail:      proto.Detail,
		CVSSScore:   proto.CvssScore,
		CVERefs:     string(cveJSON),
		RawRequest:  proto.RawRequest,
		RawResponse: proto.RawResponse,
		Module:      proto.Module,
	}
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	if err := s.store.InsertFinding(f); err != nil {
		log.Printf("[output] insert finding: %v", err)
		return
	}
	s.bus.Publish(pb.EventType_EVENT_FINDING_NEW, out.AgentId, "",
		fmt.Sprintf(`{"finding_id":%q,"title":%q,"severity":%q}`, f.ID, f.Title, f.Severity))
}

// CheckIn handles BEACON-mode agents.  The agent submits completed task
// results and receives any pending tasks queued since the last check-in.
func (s *Server) CheckIn(ctx context.Context, req *pb.BeaconCheckIn) (*pb.BeaconResponse, error) {
	agentID := req.AgentId
	if agentID == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}

	// Upsert agent.
	a := db.Agent{
		ID:     agentID,
		Status: "online",
		Mode:   "beacon",
	}
	if req.Metrics != nil {
		a.Hostname = req.Metrics.AgentName
		a.CPUPct = req.Metrics.CpuPct
		a.MemPct = req.Metrics.MemPct
		a.Load1m = req.Metrics.Load_1M
	}
	if err := s.store.UpsertAgent(a); err != nil {
		log.Printf("[beacon] upsert %s: %v", agentID, err)
	}

	// Ensure an AgentConn exists in the registry for beacon task queuing.
	if _, ok := s.registry.Get(agentID); !ok {
		info := &pb.AgentInfo{
			AgentId:  agentID,
			Hostname: a.Hostname,
			Mode:     pb.AgentMode_AGENT_MODE_BEACON,
		}
		s.registry.Register(agentID, &AgentConn{
			Info: info,
			Mode: pb.AgentMode_AGENT_MODE_BEACON,
		})
		s.bus.Publish(pb.EventType_EVENT_AGENT_CONNECTED, agentID, "",
			fmt.Sprintf(`{"agent_id":%q,"mode":"beacon"}`, agentID))
		log.Printf("[beacon] registered: %s", agentID)
	}

	// Process completed tasks from previous check-in.
	for _, completed := range req.CompletedTasks {
		if len(completed.Chunk) > 0 {
			if err := s.store.AppendTaskOutput(
				completed.TaskId, agentID, completed.Chunk, completed.IsStderr,
			); err != nil {
				log.Printf("[beacon] append output %s: %v", completed.TaskId, err)
			}
		}
		if completed.IsDone {
			if err := s.store.FinalizeTaskResult(completed.TaskId, int(completed.ExitCode)); err != nil {
				log.Printf("[beacon] finalize %s: %v", completed.TaskId, err)
			}
			_ = s.store.UpdateTaskStatus(completed.TaskId, "done")
			s.bus.Publish(pb.EventType_EVENT_TASK_COMPLETED, agentID, "",
				fmt.Sprintf(`{"task_id":%q,"exit_code":%d}`, completed.TaskId, completed.ExitCode))
		}
	}

	// Drain pending tasks for this agent.
	conn, _ := s.registry.Get(agentID)
	var pending []*pb.TaskRequest
	if conn != nil {
		pending = conn.DrainBeaconTasks()
	}

	return &pb.BeaconResponse{
		PendingTasks: pending,
		Config: &pb.BeaconConfig{
			SleepSeconds: 60,
			JitterPct:    0.1,
		},
	}, nil
}

// ── OperatorService ───────────────────────────────────────────────────────────

// Subscribe streams all server events to an operator.  It publishes
// EVENT_OPERATOR_JOINED on connection and EVENT_OPERATOR_LEFT on disconnect.
func (s *Server) Subscribe(req *pb.SubscribeRequest, stream pb.OperatorService_SubscribeServer) error {
	opID := req.OperatorId
	if opID == "" {
		opID = uuid.New().String()
	}

	ch := s.bus.Subscribe(opID)
	defer s.bus.Unsubscribe(opID)

	s.bus.Publish(pb.EventType_EVENT_OPERATOR_JOINED, "", opID,
		fmt.Sprintf(`{"operator_id":%q}`, opID))
	log.Printf("[operator] joined: %s", opID)

	defer func() {
		s.bus.Publish(pb.EventType_EVENT_OPERATOR_LEFT, "", opID,
			fmt.Sprintf(`{"operator_id":%q}`, opID))
		log.Printf("[operator] left: %s", opID)
	}()

	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(evt); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// DispatchTask resolves target agents, validates with Session Defender, and
// dispatches the task to each target (SESSION: stream.Send, BEACON: queue).
func (s *Server) DispatchTask(ctx context.Context, req *pb.DispatchRequest) (*pb.DispatchResponse, error) {
	// Session Defender validation.
	var defenderWarning string
	if !req.SkipDefender {
		valReq := &pb.ValidateCommandRequest{
			OperatorId:  req.OperatorId,
			Type:        req.Type,
			Args:        req.Args,
			TargetAgent: strings.Join(req.TargetAgents, ","),
		}
		resp := s.defender.Validate(ctx, valReq)
		if !resp.Allowed {
			return nil, status.Errorf(codes.PermissionDenied, "Defender: %s", resp.BlockReason)
		}
		defenderWarning = resp.Warning
	}

	// Resolve target agents.
	targets := s.resolveTargets(req.TargetAgents, req.TargetTags)
	if len(targets) == 0 {
		return &pb.DispatchResponse{
			AgentCount:      0,
			DefenderWarning: defenderWarning,
		}, nil
	}

	// Ensure session exists.
	sessionID := req.SessionId
	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	if err := s.store.EnsureSession(sessionID, "dispatch-"+sessionID[:8]); err != nil {
		log.Printf("[dispatch] ensure session: %v", err)
	}

	var taskIDs []string
	for _, conn := range targets {
		agentID := conn.Info.GetAgentId()
		taskID := uuid.New().String()
		taskIDs = append(taskIDs, taskID)

		tr := &pb.TaskRequest{
			TaskId:    taskID,
			SessionId: sessionID,
			Type:      req.Type,
			Args:      req.Args,
			TimeoutSec: req.TimeoutSec,
			OperatorId: req.OperatorId,
			Payload:   req.Payload,
		}

		// Insert task record into DB.
		if err := s.store.InsertTask(taskID, sessionID, req.Type.String(), agentID, req.Args); err != nil {
			log.Printf("[dispatch] insert task %s: %v", taskID, err)
		}

		// Dispatch according to agent mode.
		if conn.Mode == pb.AgentMode_AGENT_MODE_SESSION && conn.Stream != nil {
			if err := conn.Stream.Send(tr); err != nil {
				log.Printf("[dispatch] stream.Send %s: %v", agentID, err)
			}
		} else {
			conn.QueueBeaconTask(tr)
		}

		s.bus.Publish(pb.EventType_EVENT_TASK_STARTED, agentID, req.OperatorId,
			fmt.Sprintf(`{"task_id":%q,"type":%q}`, taskID, req.Type.String()))
	}

	return &pb.DispatchResponse{
		TaskIds:         taskIDs,
		AgentCount:      int32(len(targets)),
		DefenderWarning: defenderWarning,
	}, nil
}

// resolveTargets returns the set of AgentConns to dispatch to.
// Priority: explicit target_agents → target_tags → all agents (@all).
func (s *Server) resolveTargets(agentIDs, tags []string) []*AgentConn {
	seen := make(map[string]struct{})
	var out []*AgentConn

	addConn := func(c *AgentConn) {
		id := c.Info.GetAgentId()
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			out = append(out, c)
		}
	}

	if len(agentIDs) > 0 {
		for _, id := range agentIDs {
			if c, ok := s.registry.Get(id); ok {
				addConn(c)
			}
		}
	}
	for _, tag := range tags {
		for _, c := range s.registry.ByTag(tag) {
			addConn(c)
		}
	}
	// Empty target lists → broadcast to all agents.
	if len(agentIDs) == 0 && len(tags) == 0 {
		for _, c := range s.registry.All() {
			addConn(c)
		}
	}
	return out
}

// ValidateCommand delegates to the Session Defender.
func (s *Server) ValidateCommand(ctx context.Context, req *pb.ValidateCommandRequest) (*pb.ValidateCommandResponse, error) {
	return s.defender.Validate(ctx, req), nil
}

// ListAgents returns all agents from the database store (includes offline agents).
// The registry (in-memory) is merged so live connection state is reflected.
func (s *Server) ListAgents(ctx context.Context, req *pb.ListAgentsRequest) (*pb.ListAgentsResponse, error) {
	dbAgents, err := s.store.ListAgents()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list agents: %v", err)
	}

	infos := make([]*pb.AgentInfo, 0, len(dbAgents))
	for _, a := range dbAgents {
		info := &pb.AgentInfo{
			AgentId:     a.ID,
			Hostname:    a.Hostname,
			Os:          a.OS,
			Arch:        a.Arch,
			TailscaleIp: a.TailscaleIP,
			NebulaIp:    a.NebulaIP,
			Version:     a.Version,
		}
		infos = append(infos, info)
	}
	return &pb.ListAgentsResponse{Agents: infos}, nil
}

// GetSessions queries the database for sessions matching the optional status filter.
func (s *Server) GetSessions(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	rows, err := s.store.GetSessions(req.StatusFilter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get sessions: %v", err)
	}

	var sessions []*pb.SessionInfo
	for _, r := range rows {
		sessions = append(sessions, &pb.SessionInfo{
			SessionId:    r.ID,
			Name:         r.Name,
			Target:       r.Target,
			Status:       r.Status,
			CreatedAt:    r.CreatedAt,
			FindingCount: int32(r.FindingCount),
			TaskCount:    int32(r.TaskCount),
		})
	}
	return &pb.GetSessionsResponse{Sessions: sessions}, nil
}

// GetFindings queries the database for findings matching the session/severity filters.
func (s *Server) GetFindings(ctx context.Context, req *pb.GetFindingsRequest) (*pb.GetFindingsResponse, error) {
	var findings []db.Finding
	var err error

	if req.SeverityFilter != "" {
		findings, err = s.store.ListFindingsBySeverity(req.SessionId, req.SeverityFilter)
	} else {
		findings, err = s.store.ListFindings(req.SessionId)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get findings: %v", err)
	}

	var pbFindings []*pb.Finding
	for _, f := range findings {
		var cveRefs []string
		_ = json.Unmarshal([]byte(f.CVERefs), &cveRefs)

		pbFindings = append(pbFindings, &pb.Finding{
			FindingId:   f.ID,
			SessionId:   f.SessionID,
			AgentId:     f.AgentID,
			HostIp:      f.HostIP,
			Port:        int32(f.Port),
			Severity:    f.Severity,
			Title:       f.Title,
			Detail:      f.Detail,
			CvssScore:   f.CVSSScore,
			CveRefs:     cveRefs,
			RawRequest:  f.RawRequest,
			RawResponse: f.RawResponse,
			Module:      f.Module,
		})
	}
	return &pb.GetFindingsResponse{Findings: pbFindings}, nil
}

// keepAlive is a small helper used internally for ticker-based operations.
var _ = time.Second
