package rz

import (
	"encoding/json"
	"sync"
)

// Live event-streaming layer. This is a purely additive broadcast bolted onto
// the existing audit append path. It does NOT touch any rule, engine, or
// state-machine logic. When no hub is configured the entire path is inert, so
// existing commands behave byte-for-byte as before.

// BroadcastHub is the package-level hook set at startup by a command that wants
// live streaming. It is nil (inert) by default. When non-nil, every entry
// successfully written to the audit log is broadcast to its subscribers.
var BroadcastHub *StreamHub

// StreamHub fans every appended audit entry out to subscribed clients without
// ever blocking on a slow consumer.
type StreamHub struct {
	mu      sync.RWMutex
	clients map[chan []byte]bool
	first   chan struct{} // closed once the first client subscribes
}

// NewStreamHub creates an empty hub.
func NewStreamHub() *StreamHub {
	return &StreamHub{clients: map[chan []byte]bool{}, first: make(chan struct{})}
}

// Subscribe registers a new client channel and returns it. The first call to
// Subscribe (from empty) signals WaitForSubscriber.
func (h *StreamHub) Subscribe() chan []byte {
	ch := make(chan []byte, 100)
	h.mu.Lock()
	if len(h.clients) == 0 {
		select {
		case <-h.first:
		default:
			close(h.first)
		}
	}
	h.clients[ch] = true
	h.mu.Unlock()
	return ch
}

// WaitForSubscriber blocks until at least one client has subscribed. Passing a
// non-nil done channel aborts the wait when it is closed; a nil done waits
// forever.
func (h *StreamHub) WaitForSubscriber(done <-chan struct{}) {
	select {
	case <-h.first:
	case <-done:
	}
}

// Unsubscribe removes the channel and closes it. It is safe to call repeatedly
// and never blocks on the client.
func (h *StreamHub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// streamEvent wraps an audit entry with a discriminator so a consumer can tell
// a normal audit row apart from a special event type on the same stream.
type streamEvent struct {
	EventType string `json:"eventType"`
	AuditEntry
}

// Broadcast marshals the entry to JSON and sends it (non-blocking) to every
// subscribed channel.
func (h *StreamHub) Broadcast(entry AuditEntry) {
	b, err := json.Marshal(streamEvent{EventType: "audit", AuditEntry: entry})
	if err != nil {
		return
	}
	h.broadcastBytes(b)
}

// BroadcastStatus sends a special chain_status event type over the same stream.
func (h *StreamHub) BroadcastStatus(valid bool, entries int, brokenAt int) {
	b, err := json.Marshal(map[string]any{
		"eventType": "chain_status",
		"valid":     valid,
		"entries":   entries,
		"brokenAt":  brokenAt,
	})
	if err != nil {
		return
	}
	h.broadcastBytes(b)
}

// broadcastBytes is the non-blocking fan-out. The RWMutex (read lock during
// iteration + send) guarantees a concurrent Unsubscribe cannot close a channel
// while we are mid-send, and the select+default guarantee we never block on a
// slow client.
func (h *StreamHub) broadcastBytes(payload []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- payload:
		default:
			// Slow/blocked client: drop rather than stall everyone else.
		}
	}
}
