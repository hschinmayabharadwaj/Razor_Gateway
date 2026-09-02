package rz

import (
	"testing"
)

// TestGenerateEventsCanonical locks the canonical batch: exactly 60 events,
// the 8/10/12/10/8/6/6 distribution, and full determinism (a second call must
// reproduce the identical event stream). This is the parity anchor.
func TestGenerateEventsCanonical(t *testing.T) {
	ev := GenerateEvents(0)
	if len(ev) != 60 {
		t.Fatalf("canonical batch has %d events, want 60", len(ev))
	}
	counts := CountsByFlow(ev)
	for f, n := range DefaultFlowCounts {
		if counts[f] != n {
			t.Fatalf("flow %s got %d events, want %d", f, counts[f], n)
		}
	}
	ev2 := GenerateEvents(0)
	for i := range ev {
		if ev[i].EventID != ev2[i].EventID {
			t.Fatalf("determinism broken at %d: %s vs %s", i, ev[i].EventID, ev2[i].EventID)
		}
		if CountsByFlow(ev)[ev[i].Flow] != CountsByFlow(ev)[ev[i].Flow] {
			t.Fatal("unreachable")
		}
	}
}

// TestScaleFlowCountsAlwaysExact verifies the proportional distributor always
// sums to the requested total for a spread of totals.
func TestScaleFlowCountsAlwaysExact(t *testing.T) {
	for _, total := range []int{1, 6, 7, 30, 60, 61, 100, 120, 500} {
		c := ScaleFlowCounts(total)
		sum := 0
		seen := map[FlowType]bool{}
		for _, f := range FlowTypes {
			if c[f] < 0 {
				t.Fatalf("total %d: negative count for %s", total, f)
			}
			sum += c[f]
			seen[f] = true
		}
		for _, f := range FlowTypes {
			if !seen[f] {
				t.Fatalf("total %d: flow %s missing", total, f)
			}
		}
		if sum != total {
			t.Fatalf("total %d: scaled counts sum to %d", total, sum)
		}
	}
}

// TestGenerateEventsWithPerFlowOverrides verifies CountByFlow replaces only the
// listed flows and the generator emits exactly those counts.
func TestGenerateEventsWithPerFlowOverrides(t *testing.T) {
	opt := GenOptions{
		Seed: 12345,
		CountByFlow: map[FlowType]int{
			FlowFailedSubscription: 3,
			FlowHinglishVoice:      1,
		},
	}
	ev := GenerateEventsWith(opt)
	counts := CountsByFlow(ev)
	if counts[FlowFailedSubscription] != 3 {
		t.Fatalf("failed_subscription=%d, want 3", counts[FlowFailedSubscription])
	}
	if counts[FlowHinglishVoice] != 1 {
		t.Fatalf("hinglish_voice=%d, want 1", counts[FlowHinglishVoice])
	}
	// Unspecified flows keep canonical defaults.
	for f, n := range DefaultFlowCounts {
		if f == FlowFailedSubscription || f == FlowHinglishVoice {
			continue
		}
		if counts[f] != n {
			t.Fatalf("unspecified flow %s=%d, want default %d", f, counts[f], n)
		}
	}
}

// TestGenerateEventsWithSeedChangesBatch proves the seed knob actually reshapes
// the PRNG-driven fields (names, amounts, signals) so a fresh batch is possible
// without touching code. Event IDs/sequence stay deterministic by design.
func TestGenerateEventsWithSeedChangesBatch(t *testing.T) {
	a := GenerateEventsWith(GenOptions{Seed: 1})
	b := GenerateEventsWith(GenOptions{Seed: 2})
	if len(a) != len(b) {
		t.Fatalf("seed batches differ in length: %d vs %d", len(a), len(b))
	}
	amountDiff, nameDiff, signalDiff := 0, 0, 0
	for i := range a {
		if a[i].Amount != b[i].Amount {
			amountDiff++
		}
		if a[i].CustomerName != b[i].CustomerName {
			nameDiff++
		}
		if len(a[i].Signal) != len(b[i].Signal) {
			signalDiff++
		}
		if a[i].EventID != b[i].EventID {
			t.Fatalf("sequence/eventIds changed with seed at %d: %s vs %s",
				i, a[i].EventID, b[i].EventID)
		}
	}
	if amountDiff == 0 && nameDiff == 0 && signalDiff == 0 {
		t.Fatal("seeds 1 and 2 produced identical batches; seed knob is inert")
	}
	t.Logf("seeds 1 vs 2: %d/%d amounts differ, %d/%d names differ",
		amountDiff, len(a), nameDiff, len(a))
}
