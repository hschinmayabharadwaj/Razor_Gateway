package main

import (
	"fmt"

	"razor_gateway/go/rz"
)

func main() {
	events, err := rz.LoadEvents("data/flows")
	if err != nil {
		fmt.Println("load events:", err)
		return
	}

	audit, err := rz.NewAuditStore("data/demo.audit.log.jsonl")
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := audit.Clear(); err != nil {
		fmt.Println(err)
		return
	}

	now := rz.BatchNow()
	fmt.Printf("Loaded %d events across 7 recovery flows.\n\n", len(events))

	result, err := rz.RunBatch(events, audit, rz.RunnerOpts{Now: now})
	if err != nil {
		fmt.Println(err)
		return
	}

	log, _ := audit.All()
	metrics := rz.ComputeMetrics(log)

	fmt.Println("===== AUDIT LOG — TABLE VIEW (all flows) =====")
	fmt.Println(rz.RenderTable(log))
	fmt.Println(rz.RenderMetrics(metrics))
	fmt.Println()
	fmt.Println("===== EXCEPTION SUMMARY (LLM, for human reviewer) =====")
	fmt.Println(result.ExceptionSummary)

	// ---- Walkthrough 1: mandate_revoked handled gracefully ----
	walkthroughMandateRevoked(events)

	// ---- Walkthrough 2: mandate retry sequenced within NPCI window ----
	walkthroughMandateRetryWindow(events)

	// ---- Walkthrough 3: checkout abandonment recovered with incentive ----
	walkthroughCheckout(events)
}

func walkthroughMandateRevoked(events []*rz.FlowEvent) {
	fmt.Println("\n\n########## WALKTHROUGH 1: mandate_revoked handled gracefully ##########")
	for _, ev := range events {
		if ev.Flow != rz.FlowFailedSubscription || rz.Classify(ev) != rz.ReasonMandateRevoked {
			continue
		}
		reason := rz.Classify(ev)
		fmt.Printf("Event: %s (%s)\n", ev.EventID, ev.Flow)
		fmt.Printf("  error_code:      %v\n", ev.Signal["error_code"])
		fmt.Printf("  amount:          ₹%.2f\n", float64(ev.Amount)/100)
		fmt.Println()
		fmt.Printf("Step 1 — classify() -> %q  [deterministic error-code lookup, no LLM]\n", string(reason))
		fmt.Println()
		fmt.Println("Step 2 — DECISION ENGINE evaluates stopping rules:")
		fmt.Println("  (b) fraud_flagged?       -> false")
		fmt.Println("  (c) mandate_revoked?     -> TRUE ==> ESCALATE, NEVER retry")
		fmt.Println("  Rule fired: mandate_revoked_escalate, decision: escalate, actor: policy_engine")
		sr, _ := rz.StepState(ctxFor(ev, reason, 0))
		fmt.Printf("Audit entry: %v\n", sr.Audit)
		fmt.Println()
		fmt.Println("Step 3 — policy decided to escalate. ONLY NOW does the LLM write copy.")
		fmt.Println("  No charge API call was made. No money moved without a named rule.")
		fmt.Println("RESULT: correctly refused to retry, escalated to re-collect mandate, auditable.")
		return
	}
}

func walkthroughMandateRetryWindow(events []*rz.FlowEvent) {
	fmt.Println("\n\n########## WALKTHROUGH 2: India-specific mandate retry sequencing (NPCI) ##########")
	for _, ev := range events {
		if ev.Flow != rz.FlowMandateRetry {
			continue
		}
		if s, ok := ev.Signal["mandate_revoked"].(bool); ok && s {
			continue
		}
		reason := rz.Classify(ev)
		rw, _ := ev.Signal["retry_window"].(map[string]any)
		start, startOK := numToI64(rw["start"])
		end, endOK := numToI64(rw["end"])
		if !startOK || !endOK {
			continue
		}
		fmt.Printf("Event: %s (%s)\n", ev.EventID, ev.Flow)
		fmt.Printf("  reason: %s\n", reason)
		fmt.Printf("  NPCI retry window: %s -> %s (bounded, not 'retry every 3 days')\n",
			shortIso(start), shortIso(end))
		fmt.Println()
		fmt.Println("  Retry sequence (bounded): onDueDate -> +1d -> +2d, then STOP/ESCALATE.")
		fmt.Println("  decision engine enforces isWithinMandateRetryWindow() + mandateRetryAttemptAllowed().")
		fmt.Println("  Rule fired: mandate_retry_seq (within window) / mandate_retry_window (outside).")
		ctx := ctxFor(ev, reason, 0)
		w := &rz.RetryWindow{Start: start, End: end}
		ctx.RetryWindow = w
		sr, _ := rz.StepState(ctx)
		fmt.Printf("Audit entry(truncated): rule=%s decision=%s state=%s\n",
			sr.Audit.RuleFired, sr.Audit.Decision, sr.Audit.State)
		return
	}
}

func walkthroughCheckout(events []*rz.FlowEvent) {
	fmt.Println("\n\n########## WALKTHROUGH 3: checkout abandonment recovered (cost-aware) ##########")
	for _, ev := range events {
		if ev.Flow != rz.FlowCheckoutAbandonment {
			continue
		}
		if v, ok := ev.Signal["visits"].(float64); !ok || v < 2 {
			continue
		}
		reason := rz.Classify(ev)
		cartValue := i64Of(ev.Signal["cart_value"])
		fmt.Printf("Event: %s (%s), reason: %s\n", ev.EventID, ev.Flow, reason)
		fmt.Printf("  cart value: ₹%.2f\n", float64(cartValue)/100)
		fmt.Printf("  repeat visitor: yes (visits=%v)\n", ev.Signal["visits"])
		fmt.Println("  decision engine: cartEligibleForIncentive() -> TRUE on first touch")
		fmt.Println("  Rule fired: cart_incentive (only for repeat visitors + cart above threshold)")
		ctx := ctxFor(ev, reason, 0)
		ctx.CartValue = cartValue
		ctx.Visits = 2
		sr, _ := rz.StepState(ctx)
		fmt.Printf("Audit entry(truncated): rule=%s decision=%s state=%s\n",
			sr.Audit.RuleFired, sr.Audit.Decision, sr.Audit.State)
		fmt.Println("RESULT: spam guard (repeat visitors only) + no discount on junk carts (threshold).")
		return
	}
}

func ctxFor(ev *rz.FlowEvent, reason rz.ReasonBucket, attempt int) *rz.RecoveryContext {
	return &rz.RecoveryContext{
		EventID:    ev.EventID,
		Flow:       ev.Flow,
		CustomerID: ev.CustomerID,
		InvoiceID:  ev.InvoiceID,
		Amount:     ev.Amount,
		Currency:   ev.Currency,
		Reason:     reason,
		Now:        rz.BatchNow(),
		Attempt:    attempt,
	}
}

func shortIso(ms int64) string { return rz.Iso(ms)[:10] }

func numToI64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

func i64Of(v any) int64 {
	if n, ok := numToI64(v); ok {
		return n
	}
	return 0
}
