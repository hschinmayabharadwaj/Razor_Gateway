package rz

import (
	"regexp"
	"strings"
	"testing"
)

func baseEntry(over map[string]any) AuditEntry {
	e := AuditEntry{
		EventID:      "e1",
		Timestamp:    "2026-09-01T00:00:00.000Z",
		Flow:         FlowFailedSubscription,
		ReasonBucket: ReasonInsufficientFunds,
		RuleFired:    RuleTransientRetry,
		Decision:     DecisionRetry,
		Actor:        ActorPolicyEngine,
		Outcome:      "Scheduled retry",
		State:        AgentRetryScheduled,
	}
	if over != nil {
		if v, ok := over["eventId"].(string); ok {
			e.EventID = v
		}
		if v, ok := over["decision"].(string); ok {
			e.Decision = Decision(v)
		}
		if v, ok := over["attempt"].(int); ok {
			e.Attempt = intp(v)
		}
		if v, ok := over["amount"].(int); ok {
			n := int64(v)
			e.Amount = &n
		}
	}
	return e
}

func TestGenesisHashIs64Zeros(t *testing.T) {
	if GenesisHash != strings.Repeat("0", 64) {
		t.Fatalf("GenesisHash = %q, want 64 zeros", GenesisHash)
	}
	if len(GenesisHash) != 64 {
		t.Fatalf("GenesisHash length = %d", len(GenesisHash))
	}
}

func TestSha256Hex(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !re.MatchString(Sha256Hex("hello")) {
		t.Fatalf("Sha256Hex('hello') = %q not a 64-hex digest", Sha256Hex("hello"))
	}
}

func TestStableHashIndependentOfState(t *testing.T) {
	aEntry := baseEntry(map[string]any{"attempt": 1, "amount": 100})
	bEntry := baseEntry(map[string]any{"attempt": 1, "amount": 100})
	a := ComputeHash(GenesisHash, &aEntry)
	b := ComputeHash(GenesisHash, &bEntry)
	if a != b {
		t.Fatalf("stable hashes differ: %q vs %q", a, b)
	}
}

func TestHashChangesWhenContentChanges(t *testing.T) {
	e1 := baseEntry(nil)
	e2 := baseEntry(map[string]any{"decision": "escalate"})
	h1 := ComputeHash(GenesisHash, &e1)
	h2 := ComputeHash(GenesisHash, &e2)
	if h1 == h2 {
		t.Fatalf("hash did not change when decision changed")
	}
}

func TestAppendDoesNotMutateInput(t *testing.T) {
	var log []AuditEntry
	e := baseEntry(nil)
	next := AppendAuditEntry(log, e)
	if len(log) != 0 {
		t.Fatalf("input array mutated")
	}
	if len(next) != 1 {
		t.Fatalf("next length = %d", len(next))
	}
	next2 := AppendAuditEntry(next, baseEntry(map[string]any{"eventId": "e2"}))
	if len(next) != 1 {
		t.Fatalf("original still intact? len=%d", len(next))
	}
	if len(next2) != 2 {
		t.Fatalf("next2 length = %d", len(next2))
	}
}

func TestFirstEntryUsesGenesis(t *testing.T) {
	e := baseEntry(nil)
	first := AppendAuditEntry(nil, e)[0]
	if first.PrevHash != GenesisHash {
		t.Fatalf("first.prevHash = %q", first.PrevHash)
	}
	expected := ComputeHash(GenesisHash, &first)
	if first.Hash != expected {
		t.Fatalf("first.hash = %q, want %q", first.Hash, expected)
	}
}

func TestEntriesLinkToPrevious(t *testing.T) {
	var log []AuditEntry
	log = AppendAuditEntry(log, baseEntry(nil))
	log = AppendAuditEntry(log, baseEntry(map[string]any{"eventId": "e2"}))
	log = AppendAuditEntry(log, baseEntry(map[string]any{"eventId": "e3"}))
	if log[1].PrevHash != log[0].Hash {
		t.Fatalf("entry1.prevHash mismatch")
	}
	if log[2].PrevHash != log[1].Hash {
		t.Fatalf("entry2.prevHash mismatch")
	}
}

func buildChain(n int) []AuditEntry {
	var log []AuditEntry
	for i := 0; i < n; i++ {
		log = AppendAuditEntry(log, baseEntry(map[string]any{"eventId": "e" + itoa(i), "attempt": i}))
	}
	return log
}

func TestVerifyValid5EntryChain(t *testing.T) {
	res := VerifyChain(buildChain(5))
	if !res.Valid {
		t.Fatalf("expected valid chain, broke at %d", res.BrokenAtIndex)
	}
	if res.BrokenAtIndex != -1 {
		t.Fatalf("brokenAtIndex = %d, want -1", res.BrokenAtIndex)
	}
	if res.Entries != 5 {
		t.Fatalf("entries = %d", res.Entries)
	}
}

func TestVerifyDetectsFieldTampering(t *testing.T) {
	log := buildChain(5)
	log[2].Decision = DecisionEscalate
	res := VerifyChain(log)
	if res.Valid {
		t.Fatalf("expected invalid chain")
	}
	if res.BrokenAtIndex != 2 {
		t.Fatalf("brokenAtIndex = %d, want 2", res.BrokenAtIndex)
	}
}

func TestVerifyDetectsAlteredPrevHash(t *testing.T) {
	log := buildChain(3)
	log[1].PrevHash = strings.Repeat("x", 64)
	res := VerifyChain(log)
	if res.Valid {
		t.Fatalf("expected invalid chain")
	}
	if res.BrokenAtIndex != 1 {
		t.Fatalf("brokenAtIndex = %d, want 1", res.BrokenAtIndex)
	}
}
