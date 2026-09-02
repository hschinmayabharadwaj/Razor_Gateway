package rz

import (
	"path/filepath"
	"sync"
	"testing"
)

// testAuditStore builds an isolated audit store in a temp dir.
func testAuditStore(t *testing.T) *AuditStore {
	t.Helper()
	s, err := NewAuditStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func countRule(log []AuditEntry, r RuleId) int {
	n := 0
	for _, e := range log {
		if e.RuleFired == r {
			n++
		}
	}
	return n
}

// countEventEntries counts every chain row touching one event ID (execution
// domain, not idempotency-suppression rows).
func countEventEntries(log []AuditEntry, eventID string) int {
	n := 0
	for _, e := range log {
		if e.EventID == eventID && e.RuleFired != RuleDuplicateSuppress {
			n++
		}
	}
	return n
}

// TestRunBatchSuppressesDuplicatesOnReplay proves the idempotency gate: a
// second delivery of the same batch must generate zero execution activity —
// only duplicate_suppress rows — and the hash chain must still verify.
func TestRunBatchSuppressesDuplicatesOnReplay(t *testing.T) {
	events := GenerateEvents(0)
	audit := testAuditStore(t)

	first, err := RunBatch(events, audit, RunnerOpts{Now: BatchNow()})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRule(first.AuditEntries, RuleDuplicateSuppress); n != 0 {
		t.Fatalf("first run emitted %d duplicate_suppress rows", n)
	}

	again, err := RunBatch(events, audit, RunnerOpts{Now: BatchNow()})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Escapes) != 0 {
		t.Fatalf("duplicate delivery escalated/generated copy (%d escapes)", len(again.Escapes))
	}
	all, err := audit.All()
	if err != nil {
		t.Fatal(err)
	}
	firstRows := len(first.AuditEntries)
	wantRows := firstRows + len(events)
	if len(all) != wantRows {
		t.Fatalf("replay appended %d rows; want exactly %d (one duplicate_suppress row per event, zero re-execution)",
			len(all)-firstRows, len(events))
	}
	if n := countRule(all, RuleDuplicateSuppress); n != len(events) {
		t.Fatalf("want %d duplicate_suppress rows, got %d", len(events), n)
	}
	if v := VerifyChain(all); !v.Valid {
		t.Fatalf("chain broken after replay: %+v", v)
	}
}

// TestClaimSurvivesStoreReopen proves idempotency propagates across process
// restarts: a store opened over an existing log refuses to re-claim processed
// IDs, and Clear() resets the claim horizon for a fresh batch.
func TestClaimSurvivesStoreReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")

	s1, err := NewAuditStore(p)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := s1.Claim("evt_persist")
	if err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	// Persist a real row so the reopened store hydrates from the file.
	if err := s1.Append(AuditEntry{EventID: "evt_persist", RuleFired: RuleTransientRetry}); err != nil {
		t.Fatal(err)
	}

	s2, err := NewAuditStore(p)
	if err != nil {
		t.Fatal(err)
	}
	ok2, err := s2.Claim("evt_persist")
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("reopened store re-claimed an already-processed event")
	}
	if err := s2.Clear(); err != nil {
		t.Fatal(err)
	}
	ok3, err := s2.Claim("evt_persist")
	if err != nil {
		t.Fatal(err)
	}
	if !ok3 {
		t.Fatal("clear did not reset the claim horizon")
	}
}

// TestConcurrentDuplicateDeliveriesAtMostOnce fires the same event from many
// goroutines against one store. The atomic Claim gate must let exactly one
// delivery execute; all others become duplicate_suppress rows, and the chain
// must verify. This is the race-condition test the review demanded (run with
// -race on a 64-bit toolchain to confirm the Mutex does its job).
func TestConcurrentDuplicateDeliveriesAtMostOnce(t *testing.T) {
	events := []*FlowEvent{{
		EventID: "evt_race_1", Flow: FlowFailedSubscription,
		CustomerID: "c_race", Amount: 49900, Currency: "INR",
		Signal: map[string]any{"error_code": "CARD_DECLINED"},
	}}
	now := BatchNow()

	baseline := testAuditStore(t)
	if _, err := RunBatch(events, baseline, RunnerOpts{Now: now}); err != nil {
		t.Fatal(err)
	}
	baseLog, _ := baseline.All()
	baseExec := countEventEntries(baseLog, "evt_race_1")
	if baseExec == 0 {
		t.Fatal("baseline executed nothing; test setup wrong")
	}

	audit := testAuditStore(t)
	const goroutines = 16
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := RunBatch(events, audit, RunnerOpts{Now: now}); err != nil {
				t.Errorf("concurrent run: %v", err)
			}
		}()
	}
	wg.Wait()

	all, err := audit.All()
	if err != nil {
		t.Fatal(err)
	}
	if v := VerifyChain(all); !v.Valid {
		t.Fatalf("chain broken under concurrency: %+v", v)
	}
	if exec := countEventEntries(all, "evt_race_1"); exec != baseExec {
		t.Fatalf("execution happened %d times; want exactly %d (at-most-once violated)",
			exec, baseExec)
	}
	if n := countRule(all, RuleDuplicateSuppress); n != goroutines-1 {
		t.Fatalf("want %d duplicate_suppress rows, got %d", goroutines-1, n)
	}
}
