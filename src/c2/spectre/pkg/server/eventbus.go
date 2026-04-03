package server

import (
	"sync"
	"time"

	"github.com/google/uuid"
	pb "github.com/sbu/spectre-c2/pkg/proto"
)

// EventBus is a fan-out publish/subscribe bus for server-wide events.
// Each subscriber gets its own buffered channel. Slow subscribers are
// silently dropped (non-blocking publish) rather than blocking the publisher.
type EventBus struct {
	mu   sync.RWMutex
	subs map[string]chan *pb.Event
}

// NewEventBus creates a ready-to-use EventBus.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[string]chan *pb.Event)}
}

// Subscribe registers a subscriber with the given id and returns a channel
// on which it will receive events. Buffer size 256 prevents slow readers
// from blocking Publish.
func (b *EventBus) Subscribe(id string) chan *pb.Event {
	ch := make(chan *pb.Event, 256)
	b.mu.Lock()
	b.subs[id] = ch
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (b *EventBus) Unsubscribe(id string) {
	b.mu.Lock()
	if ch, ok := b.subs[id]; ok {
		close(ch)
		delete(b.subs, id)
	}
	b.mu.Unlock()
}

// Publish constructs an Event and delivers it to all current subscribers.
// Delivery is non-blocking: if a subscriber's buffer is full the event is
// dropped for that subscriber only.
func (b *EventBus) Publish(t pb.EventType, agentID, operatorID, payload string) {
	evt := &pb.Event{
		EventId:    uuid.New().String(),
		Type:       t,
		AgentId:    agentID,
		OperatorId: operatorID,
		Payload:    payload,
		Timestamp:  time.Now().UnixMilli(),
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- evt:
		default:
			// subscriber is slow; drop rather than block
		}
	}
}
