package rz

import "fmt"

// Compare the REAL policy engine vs the NAIVE baseline on the SAME batch.
// The naive touches are each re-checked against the REAL rule predicates; we
// count how many naive actions would have violated a named rule — violations
// the real engine structurally cannot commit.

type ViolationCounts struct {
	FraudRetries           int
	MandateRetries         int
	QuietHourCalls         int
	DNcBreaches            int
	TouchCapBreaches       int
	RetryBudgetBreaches    int
	PtpSuppressionBreaches int
	Total                  int
}

type PolicyComparison struct {
	Real              Metrics
	Naive             Metrics
	Violations        ViolationCounts
	TotalNaiveTouches int
	Takeaway          string
}

// CountComplianceViolations re-checks each naive touch against the real rules.
func CountComplianceViolations(touches []NaiveTouch) ViolationCounts {
	v := ViolationCounts{}
	uniqueViolatingActions := 0
	for _, t := range touches {
		violated := false
		if IsFraudFlagged(t.Reason) {
			v.FraudRetries++
			violated = true
		}
		if IsMandateRevoked(t.Reason) {
			v.MandateRetries++
			violated = true
		}
		if t.Channel == "voice" && IsDoNotCall(t.DNCFlag, t.Now) {
			if t.DNCFlag {
				v.DNcBreaches++
			} else {
				v.QuietHourCalls++
			}
			violated = true
		}
		if AtTouchCap(t.TouchesForCustomer) {
			v.TouchCapBreaches++
			violated = true
		}
		if AtMaxRetryAttempts(t.Attempt) {
			v.RetryBudgetBreaches++
			violated = true
		}
		if HasActivePromiseToPay(t.ActivePromiseToPayDate, t.Now) {
			v.PtpSuppressionBreaches++
			violated = true
		}
		if violated {
			uniqueViolatingActions++
		}
	}
	// headline = unique naive ACTIONS that violate at least one named rule
	v.Total = uniqueViolatingActions
	return v
}

// ComparePolicies runs both policies on the same batch into two audit stores.
func ComparePolicies(events []*FlowEvent, realAudit, naiveAudit *AuditStore, now int64) (PolicyComparison, error) {
	if now == 0 {
		now = nowEpoch()
	}
	if err := realAudit.Clear(); err != nil {
		return PolicyComparison{}, err
	}
	if err := naiveAudit.Clear(); err != nil {
		return PolicyComparison{}, err
	}

	if _, err := RunBatch(events, realAudit, RunnerOpts{Now: now}); err != nil {
		return PolicyComparison{}, err
	}
	naive, err := RunNaiveBatch(events, naiveAudit, NaiveOpts{Now: now})
	if err != nil {
		return PolicyComparison{}, err
	}

	realLog, err := realAudit.All()
	if err != nil {
		return PolicyComparison{}, err
	}
	naiveLog, err := naiveAudit.All()
	if err != nil {
		return PolicyComparison{}, err
	}

	real := ComputeMetrics(realLog)
	naiveMetrics := ComputeMetrics(naiveLog)

	violations := CountComplianceViolations(naive.Touches)
	totalNaiveTouches := len(naive.Touches)
	takeaway := BuildTakeaway(real, naiveMetrics, violations)

	return PolicyComparison{
		Real:              real,
		Naive:             naiveMetrics,
		Violations:        violations,
		TotalNaiveTouches: totalNaiveTouches,
		Takeaway:          takeaway,
	}, nil
}

// One-line takeaway computed from the data, not hard-coded.
func BuildTakeaway(real, naive Metrics, v ViolationCounts) string {
	realRate := fmt.Sprintf("%.1f", real.RecoveryRate*100)
	naiveRate := fmt.Sprintf("%.1f", naive.RecoveryRate*100)
	rateDelta := (naive.RecoveryRate - real.RecoveryRate) * 100
	deltaStr := fmt.Sprintf("%.1f", rateDelta)
	if rateDelta >= 0 {
		deltaStr = "+" + deltaStr
	}
	realTouches := real.TouchesSent
	naiveTouches := naive.TouchesSent
	return "Naive retry recovers " + naiveRate + "% vs " + realRate + "% (" + deltaStr + "pp) but commits " +
		itoa(v.Total) + " compliance violations (" +
		itoa(v.FraudRetries) + " fraud retries, " +
		itoa(v.MandateRetries) + " mandate revoke retries, " +
		itoa(v.QuietHourCalls) + " quiet-hour calls, " +
		itoa(v.DNcBreaches) + " DNC breaches, " +
		itoa(v.TouchCapBreaches) + " touch-cap breaches, " +
		itoa(v.RetryBudgetBreaches) + " retry-budget breaches, " +
		itoa(v.PtpSuppressionBreaches) + " PTP breaches) and " +
		itoa(naiveTouches) + " touches (vs " + itoa(realTouches) + ") — violations our policy engine structurally cannot make."
}

// RenderComparison renders the comparison table.
func RenderComparison(c PolicyComparison) string {
	var out []string
	out = append(out, "")
	out = append(out, "===== POLICY COMPARISON (same 60-event batch) =====")
	header := []string{"metric", "real_policy", "naive_policy", "delta"}
	realRate := c.Real.RecoveryRate * 100
	naiveRate := c.Naive.RecoveryRate * 100
	rows := [][]string{
		{"recovery_rate", pct(realRate), pct(naiveRate), signed(naiveRate-realRate) + "pp"},
		{"recovered_amount", "₹" + fmt.Sprintf("%.2f", c.Real.RecoveredRupees), "₹" + fmt.Sprintf("%.2f", c.Naive.RecoveredRupees), signed(c.Naive.RecoveredRupees-c.Real.RecoveredRupees) + "₹"},
		{"touches_sent", itoa(c.Real.TouchesSent), itoa(c.Naive.TouchesSent), signed(float64(c.Naive.TouchesSent) - float64(c.Real.TouchesSent))},
		{"cost_per_recovery", cp(c.Real), cp(c.Naive), ""},
		{"avg_touches_per_customer", avg(c.Real), avg(c.Naive), ""},
		{"compliance_violations", "0", itoa(c.Violations.Total), "+" + itoa(c.Violations.Total)},
		{"unrecoverable_risk_touched", "0", itoa(c.Violations.FraudRetries + c.Violations.MandateRetries), ""},
	}
	out = append(out, renderGrid(header, rows))
	out = append(out, "")
	out = append(out, "===== NAIVE VIOLATIONS BREAKDOWN (re-checked vs real rules) =====")
	ih := []string{"violation", "count"}
	ir := [][]string{
		{"fraud_flagged retries", itoa(c.Violations.FraudRetries)},
		{"mandate_revoked retries", itoa(c.Violations.MandateRetries)},
		{"TRAI quiet-hour calls", itoa(c.Violations.QuietHourCalls)},
		{"DNC breaches", itoa(c.Violations.DNcBreaches)},
		{"customer touch-cap breaches", itoa(c.Violations.TouchCapBreaches)},
		{"retry-budget (10 vs 3) overage", itoa(c.Violations.RetryBudgetBreaches)},
		{"PTP-suppression breaches", itoa(c.Violations.PtpSuppressionBreaches)},
		{"TOTAL", itoa(c.Violations.Total)},
	}
	out = append(out, renderGrid(ih, ir))
	out = append(out, "")
	out = append(out, "TAKEAWAY:")
	out = append(out, "  "+c.Takeaway)
	return joinLines(out)
}

func pct(x float64) string { return fmt.Sprintf("%.1f", x) + "%" }

func signed(x float64) string {
	if x >= 0 {
		return "+" + fmt.Sprintf("%.0f", x)
	}
	return fmt.Sprintf("%.0f", x)
}

func cp(m Metrics) string { return fmt.Sprintf("%.2f", m.CostPerRecovery) + "/rec" }

func avg(m Metrics) string {
	n := float64(m.TouchesSent)
	d := float64(m.TotalEvents)
	if d < 1 {
		d = 1
	}
	return fmt.Sprintf("%.2f", n/d)
}

func nowEpoch() int64 {
	return epochMS()
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
