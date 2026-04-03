package server

import (
	"sync"

	pb "github.com/sbu/spectre-c2/pkg/proto"
)

// AgentConn holds the live connection state for one agent.
// SESSION agents have an active bidirectional gRPC stream.
// BEACON agents have a nil Stream and queue tasks for the next check-in.
type AgentConn struct {
	Info   *pb.AgentInfo
	Stream pb.AgentService_ConnectServer // nil for beacon agents
	Mode   pb.AgentMode

	// Beacon-mode pending tasks queue; protected by mu.
	PendingTasks []*pb.TaskRequest
	mu           sync.Mutex
}

// QueueBeaconTask appends a task to the agent's pending queue.
// Safe for concurrent use.
func (c *AgentConn) QueueBeaconTask(t *pb.TaskRequest) {
	c.mu.Lock()
	c.PendingTasks = append(c.PendingTasks, t)
	c.mu.Unlock()
}

// DrainBeaconTasks atomically returns all pending tasks and clears the queue.
// Safe for concurrent use.
func (c *AgentConn) DrainBeaconTasks() []*pb.TaskRequest {
	c.mu.Lock()
	tasks := c.PendingTasks
	c.PendingTasks = nil
	c.mu.Unlock()
	return tasks
}

// Registry maintains the set of currently connected agents.
// All methods are safe for concurrent use.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*AgentConn
}

// NewRegistry returns a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]*AgentConn)}
}

// Register adds or replaces an agent connection in the registry.
func (r *Registry) Register(id string, conn *AgentConn) {
	r.mu.Lock()
	r.agents[id] = conn
	r.mu.Unlock()
}

// Remove deletes an agent from the registry.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.agents, id)
	r.mu.Unlock()
}

// Get returns the AgentConn for the given id, or (nil, false) if not present.
func (r *Registry) Get(id string) (*AgentConn, bool) {
	r.mu.RLock()
	c, ok := r.agents[id]
	r.mu.RUnlock()
	return c, ok
}

// All returns a snapshot of every registered AgentConn.
func (r *Registry) All() []*AgentConn {
	r.mu.RLock()
	out := make([]*AgentConn, 0, len(r.agents))
	for _, c := range r.agents {
		out = append(out, c)
	}
	r.mu.RUnlock()
	return out
}

// ByTag returns all agents whose Info.Tags contains the given tag string.
func (r *Registry) ByTag(tag string) []*AgentConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*AgentConn
	for _, c := range r.agents {
		if c.Info == nil {
			continue
		}
		for _, t := range c.Info.Tags {
			if t == tag {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// Infos returns a snapshot of all non-nil AgentInfo records.
func (r *Registry) Infos() []*pb.AgentInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*pb.AgentInfo, 0, len(r.agents))
	for _, c := range r.agents {
		if c.Info != nil {
			out = append(out, c.Info)
		}
	}
	return out
}
