package rz

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// streamServer is a minimal stdlib net/http server (no framework) that exposes
// the live audit stream, chain verification, and the JSON adapter surfaces for
// the Blazor frontend. It reads state from the audit store and pushes events
// over the hub. It performs NO rule evaluation or policy decision of its own —
// every number it returns is produced by the existing Go logic (ComputeMetrics,
// ComparePolicies, ComputePrescoreReport, RunSandbox, VerifyChain). It only
// shapes those results into JSON and applies the deny-by-default role gate.

type streamServer struct {
	audit  *AuditStore
	hub    *StreamHub
	mode   ExecutionMode
	events []*FlowEvent
}

// StartStreamServer binds an HTTP server on addr (e.g. ":8090") and serves in a
// background goroutine. The returned *http.Server can be Shutdown'ed by the
// caller; the caller is responsible for keeping the process alive. Events are
// loaded on demand from data/flows for the compute-heavy endpoints.
func StartStreamServer(audit *AuditStore, hub *StreamHub, addr string) (*http.Server, error) {
	s := &streamServer{audit: audit, hub: hub, mode: ModeSandbox}
	if evts, err := LoadEvents("data/flows"); err == nil {
		s.events = evts
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/chain-status", s.handleChainStatus)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/exceptions", s.handleExceptions)
	mux.HandleFunc("/compare-policy", s.handleComparePolicy)
	mux.HandleFunc("/prescore", s.handlePrescore)
	mux.HandleFunc("/sandbox", s.handleSandbox)
	mux.HandleFunc("/demo/tamper", s.handleTamper)

	srv := &http.Server{Addr: addr, Handler: mux}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	return srv, nil
}

// handleEvents is the Server-Sent Events endpoint.
func (s *streamServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)

	// Replay existing entries first so a freshly-connected client sees the
	// full audit history before it switches to live events.
	if entries, err := s.audit.All(); err == nil {
		for _, e := range entries {
			b, merr := json.Marshal(streamEvent{EventType: "audit", AuditEntry: e})
			if merr != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	} else {
		fmt.Fprintf(w, "data: %s\n\n", `{"eventType":"chain_status","valid":false,"entries":0,"brokenAt":null}`)
		fl.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			fl.Flush()
		}
	}
}

type chainStatus struct {
	Valid    bool `json:"valid"`
	Entries  int  `json:"entries"`
	BrokenAt *int `json:"brokenAt"`
}

// handleChainStatus calls VerifyChain on demand and returns plain JSON.
func (s *streamServer) handleChainStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionVerifyAnchor); !ok {
		return
	}
	entries, err := s.audit.All()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := VerifyChain(entries)
	status := chainStatus{Valid: v.Valid, Entries: v.Entries}
	if !v.Valid {
		n := v.BrokenAtIndex
		status.BrokenAt = &n
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// handleMetrics returns the metrics dashboard (including the eligible-vs-blocked
// segmentation) computed from the current audit log.
func (s *streamServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	m := ComputeMetrics(log)
	resp := buildMetricsJSON(m)
	resp.Eligibility = ComputeEligibility(log)
	writeJSON(w, http.StatusOK, resp)
}

// handleExceptions returns the human-review exception list, PII-redacted
// server-side.
func (s *streamServer) handleExceptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadExceptionList); !ok {
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	m := ComputeMetrics(log)
	writeJSON(w, http.StatusOK, map[string]any{
		"exceptions": buildExceptionsJSON(m.ExceptionList),
	})
}

// handleComparePolicy re-runs the real-vs-naive comparison and returns it as
// JSON.
func (s *streamServer) handleComparePolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return
	}
	realAudit, err := NewAuditStore("data/audit.real.jsonl")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	naiveAudit, err := NewAuditStore("data/audit.naive.jsonl")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	c, err := ComparePolicies(s.events, realAudit, naiveAudit, BatchNow())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	v := c.Violations
	writeJSON(w, http.StatusOK, comparisonJSON{
		Real:              buildMetricsJSON(c.Real),
		Naive:             buildMetricsJSON(c.Naive),
		TotalNaiveTouches: c.TotalNaiveTouches,
		Takeaway:          c.Takeaway,
		Violations: violationsJSON{
			FraudRetries:           v.FraudRetries,
			MandateRetries:         v.MandateRetries,
			QuietHourCalls:         v.QuietHourCalls,
			DNcBreaches:            v.DNcBreaches,
			TouchCapBreaches:       v.TouchCapBreaches,
			RetryBudgetBreaches:    v.RetryBudgetBreaches,
			PtpSuppressionBreaches: v.PtpSuppressionBreaches,
			Total:                  v.Total,
		},
	})
}

// handlePrescore computes the risk-prescore report retroactively against the
// current audit log.
func (s *streamServer) handlePrescore(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	report := ComputePrescoreReport(s.events, log, 0)
	writeJSON(w, http.StatusOK, buildPrescoreJSON(report))
}

// handleSandbox runs the tunable sweep and returns every scenario plus the
// locked-rule invariant. The optional ?scenario=X param selects which scenario
// is highlighted; all scenarios are returned for the comparison table.
func (s *streamServer) handleSandbox(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionTuneSandbox); !ok {
		return
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return
	}
	selected := r.URL.Query().Get("scenario")
	report, err := RunSandbox(s.events, BatchNow())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	writeJSON(w, http.StatusOK, buildSandboxJSON(report, selected))
}

// handleTamper is a demo-only endpoint gated behind an explicit ExecutionMode
// sandbox check (reusing the sandbox-isolation pattern from execution.go) AND
// the admin-only tune_sandbox role. It flips one field on an IN-MEMORY COPY of
// the log (never the real file), re-runs VerifyChain on the copy, and broadcasts
// the result as a chain_status event.
func (s *streamServer) handleTamper(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionTuneSandbox); !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.mode != ModeSandbox {
		http.Error(w, "demo tamper is sandbox-only", http.StatusForbidden)
		return
	}
	entries, err := s.audit.All()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	copy := make([]AuditEntry, len(entries))
	for i := range entries {
		copy[i] = entries[i]
	}
	if len(copy) > 0 {
		copy[0].Decision = DecisionEscalate
	}

	s.broadcastChainStatus(copy)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

// broadcastChainStatus runs VerifyChain over the given (possibly tampered)
// copy and pushes the authoritative result to every subscriber.
func (s *streamServer) broadcastChainStatus(log []AuditEntry) {
	v := VerifyChain(log)
	s.hub.BroadcastStatus(v.Valid, v.Entries, v.BrokenAtIndex)
}
