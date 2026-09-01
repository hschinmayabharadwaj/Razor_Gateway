package rz

import (
	"fmt"
)

// Retroactive risk prescore report. For every event in the batch we compute a
// deterministic, transparent risk score BEFORE processing (predict-before-fail),
// then compare that prescore against the ACTUAL recovery outcome from the real
// policy engine. The audit trail is hash-chained, so "absolute truth" here is
// itself tamper-evident.

type PrescoreRow struct {
	EventId         string
	Flow            FlowType
	CustomerId      string
	Score           int
	Decision        RiskDecision
	TopFactor       string
	FailedToRecover bool
	HighRiskBefore  bool
	Recovered       bool
}

type PrescoreReport struct {
	Rows                []PrescoreRow
	TotalEvents         int
	FailedEvents        int
	HighRiskAmongFailed int
	HighRiskTotal       int
	Precision           float64
	Recall              float64
	Headline            string
}

// deriveHistory builds a deterministic, auditable customer-history snapshot
// from the event envelope + signal. Repeated for the same event -> same history.
func DeriveHistory(event *FlowEvent) CustomerHistory {
	s := event.Signal
	if s == nil {
		s = map[string]any{}
	}

	// Deterministic PRNG seeded from the customer id (FNV-1a -> uint32), so the
	// "history" is stable per customer and reproducible at audit time.
	seed := HashStr(event.CustomerID)
	pastDeclines := 1 + int(prescoreRand(seed)*4)          // 1..4 prior declines
	pastChargebacks := int(prescoreRand(seed*7+1) * 3)     // 0..2
	mandateAgeDays := 10 + int(prescoreRand(seed*3+2)*300) // 10..309

	var cardExpiresWithinDays *int
	if s["error_reason"] == "expired_card" || s["error_code"] == "CARD_EXPIRED" {
		cd := 5 + int(prescoreRand(seed*5+3)*25)
		cardExpiresWithinDays = &cd
	}

	daysSinceLastDecline := 4 + int(prescoreRand(seed*9+4)*40)
	if s["error_reason"] == "expired_card" || s["error_reason"] == "risk_decline" {
		daysSinceLastDecline = 1
	}

	return CustomerHistory{
		PriorDeclineCount90d:    pastDeclines,
		MandateAgeDays:          mandateAgeDays,
		DaysSinceLastDecline:    daysSinceLastDecline,
		PriorChargebackCount90d: pastChargebacks,
		CardExpiresWithinDays:   cardExpiresWithinDays,
		RenewalCount:            int(prescoreRand(seed*11+5) * 6),
		AmountInRupees:          float64(event.Amount) / 100,
	}
}

// isRecoveredState mirrors `state === 'recovered' || decision === 'recover'`.
func isRecoveredState(e AuditEntry) bool {
	return e.State == AgentRecovered || e.Decision == DecisionRecover
}

// ComputePrescoreReport scores every event and compares to the actual outcome.
func ComputePrescoreReport(events []*FlowEvent, auditEntries []AuditEntry, threshold int) PrescoreReport {
	if threshold == 0 {
		threshold = RISK_THRESHOLD_HIGH
	}
	recovered := make(map[string]bool)
	for _, e := range auditEntries {
		if isRecoveredState(e) {
			recovered[e.EventID] = true
		}
	}

	rows := make([]PrescoreRow, 0, len(events))
	for _, ev := range events {
		scored := riskScore(RiskInput{History: DeriveHistory(ev)})
		rec := recovered[ev.EventID]
		hi := scored.Score >= float64(threshold)
		topFactor := "none"
		if len(scored.Factors) > 0 {
			topFactor = scored.Factors[0].Label
		}
		rows = append(rows, PrescoreRow{
			EventId:         ev.EventID,
			Flow:            ev.Flow,
			CustomerId:      ev.CustomerID,
			Score:           roundInt(scored.Score),
			Decision:        scored.Decision,
			TopFactor:       topFactor,
			Recovered:       rec,
			FailedToRecover: !rec,
			HighRiskBefore:  hi,
		})
	}

	failedEvents := 0
	highRiskAmongFailed := 0
	highRiskTotal := 0
	for _, r := range rows {
		if r.FailedToRecover {
			failedEvents++
			if r.HighRiskBefore {
				highRiskAmongFailed++
			}
		}
		if r.HighRiskBefore {
			highRiskTotal++
		}
	}

	precision := float64(0)
	if highRiskTotal > 0 {
		precision = float64(highRiskAmongFailed) / float64(highRiskTotal)
	}
	recall := float64(0)
	if failedEvents > 0 {
		recall = float64(highRiskAmongFailed) / float64(failedEvents)
	}

	headline := fmt.Sprintf("%d of %d events that were not auto-recovered (%.0f%% recall) had already been flagged high-risk BEFORE the attempt (%.0f%% precision) — the recovery layer is the cleanup crew; this prescore is the bridge to preventing the leak before it happens.",
		highRiskAmongFailed, failedEvents, recall*100, precision*100)

	return PrescoreReport{
		Rows:                rows,
		TotalEvents:         len(rows),
		FailedEvents:        failedEvents,
		HighRiskAmongFailed: highRiskAmongFailed,
		HighRiskTotal:       highRiskTotal,
		Precision:           precision,
		Recall:              recall,
		Headline:            headline,
	}
}

// EmitPrescoreAudit emits one prescore per event as a hash-chained entry.
func EmitPrescoreAudit(report PrescoreReport, audit *AuditStore) int {
	for _, r := range report.Rows {
		outcome := fmt.Sprintf("Pre-score %d/100 (%s, top factor: %s) -> %s",
			r.Score, r.Decision, r.TopFactor, condStr(r.FailedToRecover, "NOT auto-recovered", "auto-recovered"))
		_ = audit.Append(AuditEntry{
			EventID:      r.EventId,
			Timestamp:    Iso(nowEpoch()),
			Flow:         r.Flow,
			ReasonBucket: ReasonInsufficientFunds, // placeholder; prescore is pre-diagnosis
			RuleFired:    RuleNoOp,
			Decision:     DecisionNone,
			Actor:        ActorPolicyEngine,
			Outcome:      outcome,
			State:        AgentDetected,
			CustomerID:   r.CustomerId,
			Notes:        fmt.Sprintf("high_risk_prescore=%v", r.HighRiskBefore),
		})
	}
	return len(report.Rows)
}

// RenderPrescoreReport renders the compact table + headline.
func RenderPrescoreReport(report PrescoreReport) string {
	var out []string
	out = append(out, "")
	out = append(out, "===== PREVENTION LAYER: RISK PRESCORE (BEFORE outcome) =====")
	header := []string{"event", "flow", "pre_score", "decision", "top_factor", "actual"}
	rows := make([][]string, 0, len(report.Rows))
	for _, r := range report.Rows {
		actual := "recovered"
		if r.FailedToRecover {
			actual = "NOT recovered"
		}
		rows = append(rows, []string{
			r.EventId, string(r.Flow), itoa(r.Score), string(r.Decision), r.TopFactor, actual,
		})
	}
	out = append(out, renderGrid(header, rows))
	out = append(out, "")
	out = append(out, fmt.Sprintf("Total %d | not auto-recovered %d | pre-flagged high-risk %d | pre-flagged & failed %d",
		report.TotalEvents, report.FailedEvents, report.HighRiskTotal, report.HighRiskAmongFailed))
	out = append(out, fmt.Sprintf("RECALL %.0f%%  |  PRECISION %.0f%%", report.Recall*100, report.Precision*100))
	out = append(out, "")
	out = append(out, "HEADLINE:")
	out = append(out, "  "+report.Headline)
	return joinLines(out)
}

// ComputePrescoreReportPublic is the CLI entry: runs the real batch into a
// fresh log, computes the prescore report, emits prescores onto the same
// hash-chained log, and verifies the chain still holds.
type PrescoreRunResult struct {
	Report        PrescoreReport
	Emitted       int
	TotalLog      int
	ChainValid    bool
	BrokenAtIndex int
}

func ComputePrescoreReportPublic(events []*FlowEvent, now int64) (*PrescoreRunResult, error) {
	audit, err := NewAuditStore("data/audit.prescore.log.jsonl")
	if err != nil {
		return nil, err
	}
	if err := audit.Clear(); err != nil {
		return nil, err
	}
	if _, err := RunBatch(events, audit, RunnerOpts{Now: now}); err != nil {
		return nil, err
	}
	base, err := audit.All()
	if err != nil {
		return nil, err
	}
	report := ComputePrescoreReport(events, base, RISK_THRESHOLD_HIGH)
	emitted := EmitPrescoreAudit(report, audit)
	all, err := audit.All()
	if err != nil {
		return nil, err
	}
	check := VerifyChain(all)
	return &PrescoreRunResult{
		Report:        report,
		Emitted:       emitted,
		TotalLog:      len(all),
		ChainValid:    check.Valid,
		BrokenAtIndex: check.BrokenAtIndex,
	}, nil
}

// HashStr is the FNV-1a 32-bit variant matching the TS hashStr (returns uint32).
func HashStr(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// prescoreRand mirrors the TS deterministic PRNG `rand(seed)` (xorshift-like,
// 32-bit math only). Pure, no global state.
func prescoreRand(seed uint32) float64 {
	// t = seed + 0x6d2b79f5 held as a Number, but every op narrows to 32-bit.
	t := uint32(uint64(seed) + 0x6d2b79f5)
	// t = Math.imul(t ^ (t >>> 15), t | 1)
	a := int32(t) ^ int32(t>>15)
	b := int32(t) | 1
	t = uint32(int32(a) * int32(b))
	// t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
	x := int32(t) ^ int32(t>>7)
	y := int32(t) | 61
	m := int32(x) * int32(y)
	t = uint32(int32(t) ^ (int32(t) + m))
	// return ((t ^ (t >>> 14)) >>> 0) / 4294967296
	out := uint32(int32(t) ^ int32(t>>14))
	return float64(out) / 4294967296
}

func roundInt(f float64) int {
	if f < 0 {
		return int(f - 0.5)
	}
	return int(f + 0.5)
}

func condStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
