package rz

import (
	"encoding/json"
	"testing"
)

// decodeAudit extracts the embedded audit payload from a broadcast frame.
func decodeAudit(t *testing.T, payload []byte) streamEvent {
	t.Helper()
	var ev streamEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		t.Fatalf("unmarshal broadcast: %v (payload=%s)", err, payload)
	}
	return ev
}

func TestBroadcastDeliversToAllSubscribers(t *testing.T) {
	h := NewStreamHub()
	ch1 := h.Subscribe()
	ch2 := h.Subscribe()

	h.Broadcast(baseEntry(nil))

	e1 := decodeAudit(t, <-ch1)
	if e1.EventType != "audit" {
		t.Fatalf("ch1 eventType = %q, want audit", e1.EventType)
	}
	if e1.EventID != "e1" {
		t.Fatalf("ch1 EventID = %q, want e1", e1.EventID)
	}

	e2 := decodeAudit(t, <-ch2)
	if e2.EventID != "e1" {
		t.Fatalf("ch2 EventID = %q, want e1", e2.EventID)
	}
}

func TestBroadcastStatusReachesSubscribers(t *testing.T) {
	h := NewStreamHub()
	ch := h.Subscribe()
	h.BroadcastStatus(false, 5, 2)

	payload := <-ch
	var ev map[string]any
	if err := json.Unmarshal(payload, &ev); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if ev["eventType"] != "chain_status" {
		t.Fatalf("eventType = %v, want chain_status", ev["eventType"])
	}
	if ev["valid"] != false || ev["entries"] != float64(5) || ev["brokenAt"] != float64(2) {
		t.Fatalf("unexpected status payload: %v", ev)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	h := NewStreamHub()
	ch := h.Subscribe()
	other := h.Subscribe()

	h.Unsubscribe(ch)

	// Broadcast must neither panic (it must not send on the closed channel) nor
	// drop delivery to the remaining subscriber.
	h.Broadcast(baseEntry(nil))

	select {
	case <-other:
		// surviving subscriber still receives — good
	default:
		t.Fatalf("surviving subscriber missed broadcast after unsubscribe")
	}

	select {
	case v, ok := <-ch:
		if ok {
			t.Fatalf("unsubscribed channel still received data")
		}
		// closed -> ok == false; expected, delivery has stopped
		_ = v
	default:
	}
}

func TestSlowClientDoesNotBlockBroadcast(t *testing.T) {
	h := NewStreamHub()

	// A channel we deliberately NEVER drain, with a tiny buffer. Once full, a
	// blocking send would hang the whole hub; the select+default must drop for
	// it instead.
	slow := make(chan []byte, 1)
	h.mu.Lock()
	h.clients[slow] = true
	h.mu.Unlock()

	fast := h.Subscribe()

	for i := 0; i < 100; i++ {
		h.Broadcast(baseEntry(map[string]any{"eventId": "e" + itoa(i)}))
	}

	// Drain whatever the fast client received — the point is the loop above
	// returned at all, so Broadcast never blocked on the full slow channel.
	got := 0
	for {
		select {
		case <-fast:
			got++
		default:
			if got == 0 {
				t.Fatalf("fast client received nothing; Broadcast likely blocked")
			}
			return
		}
	}
}
