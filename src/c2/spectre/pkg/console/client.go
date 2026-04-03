package console

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	pb "github.com/sbu/spectre-c2/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the operator gRPC connection.
type Client struct {
	conn     *grpc.ClientConn
	operator pb.OperatorServiceClient
	OpID     string
}

// Connect dials the server and returns a Client.
// addr example: "127.0.0.1:7443"
// For now uses insecure — mTLS added in M6.
func Connect(addr, operatorID string) (*Client, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(64*1024*1024),
			grpc.MaxCallSendMsgSize(64*1024*1024),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &Client{
		conn:     conn,
		operator: pb.NewOperatorServiceClient(conn),
		OpID:     operatorID,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() { c.conn.Close() }

// ListAgents returns connected agent info from the server.
func (c *Client) ListAgents(ctx context.Context) ([]*pb.AgentInfo, error) {
	resp, err := c.operator.ListAgents(ctx, &pb.ListAgentsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Agents, nil
}

// Dispatch sends a task to target agents and returns (taskIDs, agentCount, warning, error).
func (c *Client) Dispatch(ctx context.Context, sessionID string, taskType pb.TaskType, args []string, targets []string, tags []string, timeoutSec int64) ([]string, int32, string, error) {
	resp, err := c.operator.DispatchTask(ctx, &pb.DispatchRequest{
		SessionId:    sessionID,
		Type:         taskType,
		Args:         args,
		TargetAgents: targets,
		TargetTags:   tags,
		TimeoutSec:   timeoutSec,
		OperatorId:   c.OpID,
	})
	if err != nil {
		return nil, 0, "", err
	}
	return resp.TaskIds, resp.AgentCount, resp.DefenderWarning, nil
}

// GetSessions returns session list from server.
func (c *Client) GetSessions(ctx context.Context) ([]*pb.SessionInfo, error) {
	resp, err := c.operator.GetSessions(ctx, &pb.GetSessionsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

// GetFindings returns findings for a session.
func (c *Client) GetFindings(ctx context.Context, sessionID, severityFilter string) ([]*pb.Finding, error) {
	resp, err := c.operator.GetFindings(ctx, &pb.GetFindingsRequest{
		SessionId:      sessionID,
		SeverityFilter: severityFilter,
	})
	if err != nil {
		return nil, err
	}
	return resp.Findings, nil
}

// Subscribe listens for server events and calls handler for each.
// Blocks until ctx is done or stream error.
func (c *Client) Subscribe(ctx context.Context, handler func(*pb.Event)) error {
	stream, err := c.operator.Subscribe(ctx, &pb.SubscribeRequest{OperatorId: c.OpID})
	if err != nil {
		return err
	}
	for {
		evt, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		handler(evt)
	}
}

// ValidateCommand checks a command against Session Defender before dispatch.
func (c *Client) ValidateCommand(ctx context.Context, taskType pb.TaskType, args []string, targetAgent string) (*pb.ValidateCommandResponse, error) {
	return c.operator.ValidateCommand(ctx, &pb.ValidateCommandRequest{
		OperatorId:  c.OpID,
		Type:        taskType,
		Args:        args,
		TargetAgent: targetAgent,
	})
}

// parseTargets parses "@all", "@tag:scanners", "kali-01,kali-02" into (agents, tags).
// Internal helper; the exported version is ParseTargets in highlight.go.
func parseTargets(target string) (agents []string, tags []string) {
	if target == "" || target == "@all" {
		return nil, nil // empty = all
	}
	for _, t := range strings.Split(target, ",") {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, "@") {
			tags = append(tags, strings.TrimPrefix(t, "@"))
		} else {
			agents = append(agents, t)
		}
	}
	return
}

// WaitForTask polls for a task result for up to timeout, printing status to out.
// In M3, this becomes a real streaming call. For now it is a placeholder that
// returns after the timeout so the caller is not blocked indefinitely.
func (c *Client) WaitForTask(ctx context.Context, taskID string, out io.Writer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				fmt.Fprintf(out, DimStyle().Render("  [task %s: timeout waiting for result]")+"\n", taskID[:8])
				return nil
			}
		}
	}
}
