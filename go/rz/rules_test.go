package rz

import (
	"testing"
	"time"
)

func nowMs() int64 { return time.Now().UnixMilli() }

func TestRuleA_MaxRetryAttempts(t *testing.T) {
	if AtMaxRetryAttempts(0) {
		t.Fatal("atMaxRetryAttempts(0) true")
	}
	if AtMaxRetryAttempts(2) {
		t.Fatal("atMaxRetryAttempts(2) true")
	}
	if !AtMaxRetryAttempts(3) {
		t.Fatal("atMaxRetryAttempts(3) false")
	}
	if MaxRetryAttempts() != 3 {
		t.Fatalf("MAX_RETRY_ATTEMPTS() = %d, want 3", MaxRetryAttempts())
	}
}

func TestRuleB_FraudSuppressed(t *testing.T) {
	if !IsFraudFlagged(ReasonFraudFlagged) {
		t.Fatal("isFraudFlagged(fraud_flagged) false")
	}
	if IsFraudFlagged(ReasonInsufficientFunds) {
		t.Fatal("isFraudFlagged(insufficient_funds) true")
	}
	d := DecideFailedSubscription(StoppingInput{Reason: ReasonFraudFlagged, CurrentAttempt: 0, TouchesForCustomer: 0})
	if d.RuleFired != RuleFraudSuppress || d.Decision != DecisionSuppress {
		t.Fatalf("got %v/%v, want fraud_suppress/suppress", d.RuleFired, d.Decision)
	}
}

func TestRuleC_MandateRevokedEscalates(t *testing.T) {
	if !IsMandateRevoked(ReasonMandateRevoked) {
		t.Fatal("isMandateRevoked(mandate_revoked) false")
	}
	d := DecideFailedSubscription(StoppingInput{Reason: ReasonMandateRevoked, CurrentAttempt: 0, TouchesForCustomer: 0})
	if d.RuleFired != RuleMandateRevokedEsc || d.Decision != DecisionEscalate {
		t.Fatalf("got %v/%v, want mandate_revoked_escalate/escalate", d.RuleFired, d.Decision)
	}
}

func TestRuleD_PtpSuppressesRetries(t *testing.T) {
	future := nowMs() + 100000
	past := nowMs() - 100000
	d := DecideFailedSubscription(StoppingInput{Reason: ReasonInsufficientFunds, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &future, Now: nowMs()})
	if d.RuleFired != RulePromiseToPaySuppress || d.Decision != DecisionSuppress {
		t.Fatalf("got %v/%v, want promise_to_pay_suppress/suppress", d.RuleFired, d.Decision)
	}
	d2 := DecideFailedSubscription(StoppingInput{Reason: ReasonInsufficientFunds, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &past, Now: nowMs()})
	if d2.Decision != DecisionRetry {
		t.Fatalf("decision=%v, want retry", d2.Decision)
	}
	if HasActivePromiseToPay(nil, nowMs()) {
		t.Fatal("hasActivePromiseToPay({}) should be false")
	}
}

func TestRuleE_ExhaustedRetriesEscalate(t *testing.T) {
	d := DecideFailedSubscription(StoppingInput{Reason: ReasonInsufficientFunds, CurrentAttempt: 3, TouchesForCustomer: 0})
	if d.RuleFired != RuleExhaustAttemptsEscalate || d.Decision != DecisionEscalate {
		t.Fatalf("got %v/%v, want exhaust_attempts_escalate/escalate", d.RuleFired, d.Decision)
	}
	if !ExhaustedRetries(3) || ExhaustedRetries(2) {
		t.Fatal("exhaustedRetries bounds wrong")
	}
}

func TestBlastRadius_TouchCap(t *testing.T) {
	d := DecideFailedSubscription(StoppingInput{Reason: ReasonInsufficientFunds, CurrentAttempt: 0, TouchesForCustomer: 3})
	if d.RuleFired != RuleMaxTouchesCap || d.Decision != DecisionAbandon {
		t.Fatalf("got %v/%v, want max_touches_cap/abandon", d.RuleFired, d.Decision)
	}
	if MaxOutboundTouchesPerCustomer() != 3 {
		t.Fatalf("MAX_OUTBOUND_TOUCHES_PER_CUSTOMER() = %d, want 3", MaxOutboundTouchesPerCustomer())
	}
}

func TestRetryableTaxonomy(t *testing.T) {
	for _, r := range []ReasonBucket{ReasonInsufficientFunds, ReasonCardExpired, ReasonBankDeclinedTransien, ReasonAuth3dsAbandoned} {
		if !IsRetryable(r) {
			t.Fatalf("isRetryable(%s) false", r)
		}
	}
	for _, r := range []ReasonBucket{ReasonFraudFlagged, ReasonMandateRevoked} {
		if IsRetryable(r) {
			t.Fatalf("isRetryable(%s) true", r)
		}
	}
	d := DecideFailedSubscription(StoppingInput{Reason: ReasonBankDeclinedTransien, CurrentAttempt: 0, TouchesForCustomer: 0})
	if d.Decision != DecisionRetry {
		t.Fatalf("decision=%v, want retry", d.Decision)
	}
}

func TestMandateRetryWindow(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	window := &RetryWindow{Start: start, End: start + 3*86400000}

	if !IsWithinMandateRetryWindow(start+86400000, window) {
		t.Fatal("inside window should be true")
	}
	if IsWithinMandateRetryWindow(start-1, window) {
		t.Fatal("before window should be false")
	}
	if IsWithinMandateRetryWindow(window.End+1, window) {
		t.Fatal("after window should be false")
	}

	if !MandateRetryAttemptAllowed(0, start, window) {
		t.Fatal("attempt 0 on due date should be allowed")
	}
	if !MandateRetryAttemptAllowed(1, start+86400000, window) {
		t.Fatal("attempt 1 at +1d should be allowed")
	}
	if MandateRetryAttemptAllowed(3, start+3*86400000, window) {
		t.Fatal("attempt 3 at +3d should NOT be allowed (window is 3 days)")
	}

	d := DecideMandateRetry(StoppingInput{Reason: ReasonInsufficientFunds, CurrentAttempt: 0, TouchesForCustomer: 0, Now: window.End + 86400000, RetryWindow: window})
	if d.RuleFired != RuleMandateRetryWindow || d.Decision != DecisionHold {
		t.Fatalf("got %v/%v, want mandate_retry_window/hold", d.RuleFired, d.Decision)
	}

	d2 := DecideMandateRetry(StoppingInput{Reason: ReasonInsufficientFunds, CurrentAttempt: 0, TouchesForCustomer: 0, Now: start, RetryWindow: window})
	if d2.Decision != DecisionRetry {
		t.Fatalf("decision=%v, want retry", d2.Decision)
	}
}

func TestCheckoutAbandonment(t *testing.T) {
	if IsRepeatVisitor(1) {
		t.Fatal("visits=1 should not be repeat")
	}
	if !IsRepeatVisitor(2) {
		t.Fatal("visits=2 should be repeat")
	}
	d := DecideCheckoutAbandonment(StoppingInput{Reason: ReasonPaymentStepAbandoned, CurrentAttempt: 0, TouchesForCustomer: 0, Visits: 1, CartValue: 100000})
	if d.Decision != DecisionAbandon {
		t.Fatalf("decision=%v, want abandon", d.Decision)
	}
	if !CartEligibleForIncentive(100000) {
		t.Fatal("cart 100000 should be incentive-eligible")
	}
	if CartEligibleForIncentive(10000) {
		t.Fatal("cart 10000 should NOT be eligible")
	}
	if !AtCheckoutReminderCap(2) {
		t.Fatal("atCheckoutReminderCap(2) false")
	}
	d2 := DecideCheckoutAbandonment(StoppingInput{Reason: ReasonPaymentStepAbandoned, CurrentAttempt: 0, TouchesForCustomer: 2, Visits: 3, CartValue: 100000})
	if d2.Decision != DecisionAbandon {
		t.Fatalf("decision=%v, want abandon", d2.Decision)
	}
	d3 := DecideCheckoutAbandonment(StoppingInput{Reason: ReasonCheckoutError, CurrentAttempt: 0, TouchesForCustomer: 0, Visits: 3, CartValue: 100000})
	if d3.Decision != DecisionEscalate {
		t.Fatalf("decision=%v, want escalate", d3.Decision)
	}
}

func TestB2BReceivables(t *testing.T) {
	if ReceivableAction(ReceivableTier(10)) != "none" {
		t.Fatal("net10 should be none")
	}
	if ReceivableAction(ReceivableTier(40)) != "remind" {
		t.Fatal("net40 should be remind")
	}
	if ReceivableAction(ReceivableTier(75)) != "smtp" {
		t.Fatal("net75 should be smtp")
	}
	if ReceivableAction(ReceivableTier(130)) != "dunning" {
		t.Fatal("net130 should be dunning")
	}
	d := DecideB2BReceivables(StoppingInput{Reason: ReasonOverdueNet60, CurrentAttempt: 0, TouchesForCustomer: 0, OverdueDays: 130})
	if d.Decision != DecisionEscalate {
		t.Fatalf("decision=%v, want escalate", d.Decision)
	}
	d2 := DecideB2BReceivables(StoppingInput{Reason: ReasonDisputedReceivable, CurrentAttempt: 0, TouchesForCustomer: 0, OverdueDays: 40})
	if d2.RuleFired != RuleDisputeHold || d2.Decision != DecisionHold {
		t.Fatalf("got %v/%v, want dispute_hold/hold", d2.RuleFired, d2.Decision)
	}
}

func TestPaymentDegradation(t *testing.T) {
	if !SuccessRateBelowThreshold(0.8) {
		t.Fatal("0.8 should be below threshold")
	}
	if SuccessRateBelowThreshold(0.98) {
		t.Fatal("0.98 should be above threshold")
	}
	d := DecidePaymentDegradation(StoppingInput{Reason: ReasonIssuerDown, CurrentAttempt: 0, TouchesForCustomer: 0})
	if d.RuleFired != RuleDegradationEscalate || d.Decision != DecisionEscalate {
		t.Fatalf("got %v/%v, want degradation_escalate/escalate", d.RuleFired, d.Decision)
	}
}

func TestHinglishVoice(t *testing.T) {
	md := func(h, m int) int64 { return time.Date(2026, 9, 1, h, m, 0, 0, time.UTC).UnixMilli() }
	if !IsDoNotCall(true, md(14, 0)) {
		t.Fatal("DNC flag should block")
	}
	if !IsDoNotCall(false, md(22, 0)) {
		t.Fatal("22:00 UTC = 03:30 IST should block")
	}
	if IsDoNotCall(false, md(14, 0)) {
		t.Fatal("14:00 UTC = 19:30 IST should NOT block")
	}
	if !AtVoiceCallCap(2) {
		t.Fatal("atVoiceCallCap(2) false")
	}
	d := DecideHinglishVoice(StoppingInput{Reason: ReasonVoiceMissedCall, CurrentAttempt: 0, TouchesForCustomer: 2, DNCFlag: false, Now: md(14, 0)})
	if d.RuleFired != RuleVoiceEscalateHuman || d.Decision != DecisionEscalate {
		t.Fatalf("got %v/%v, want voice_escalate_human/escalate", d.RuleFired, d.Decision)
	}
	d2 := DecideHinglishVoice(StoppingInput{Reason: ReasonVoiceMissedCall, CurrentAttempt: 0, TouchesForCustomer: 0, DNCFlag: true, Now: md(14, 0)})
	if d2.RuleFired != RuleVoiceDoNotCall || d2.Decision != DecisionAbandon {
		t.Fatalf("got %v/%v, want voice_do_not_call/abandon", d2.RuleFired, d2.Decision)
	}
}

func TestPromiseToPay(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC).UnixMilli()
	futurePtp := now + 2*86400000
	pastPtp := now - 86400000
	day := int64(86400000)

	d := DecidePromiseToPay(StoppingInput{Reason: ReasonPtpCommitted, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &futurePtp, Now: now, Amount: 100000})
	if d.RuleFired != RulePtpSuppress || d.Decision != DecisionSuppress {
		t.Fatalf("got %v/%v, want ptp_suppress/suppress", d.RuleFired, d.Decision)
	}

	if !PtpReminderDue(futurePtp-3600000, futurePtp) {
		t.Fatal("ptpReminderDue -1h should be true")
	}
	d2 := DecidePromiseToPay(StoppingInput{Reason: ReasonPtpCommitted, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &futurePtp, Now: futurePtp - 3600000, Amount: 100000})
	if d2.RuleFired != RulePtpReminderBefore || d2.Decision != DecisionContact {
		t.Fatalf("got %v/%v, want ptp_reminder_before/contact", d2.RuleFired, d2.Decision)
	}

	d3 := DecidePromiseToPay(StoppingInput{Reason: ReasonPtpCommitted, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &pastPtp, Now: now, Amount: 100000})
	if d3.Decision != DecisionContact {
		t.Fatalf("decision=%v, want contact", d3.Decision)
	}

	big := DecidePromiseToPay(StoppingInput{Reason: ReasonPtpCommitted, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &futurePtp, Now: now, Amount: 5000000})
	if big.Decision != DecisionEscalate {
		t.Fatalf("decision=%v, want escalate", big.Decision)
	}

	if !PtpMissed(now, pastPtp) {
		t.Fatal("ptpMissed should be true")
	}
	if !PtpNeedsSupervisor(5000000) {
		t.Fatal("ptpNeedsSupervisor(5M) should be true")
	}
	dBroken := DecidePromiseToPay(StoppingInput{Reason: ReasonPtpBroken, CurrentAttempt: 0, TouchesForCustomer: 0, ActivePromiseToPayDate: &pastPtp, Now: now, Amount: 100000})
	if dBroken.Decision != DecisionEscalate {
		t.Fatalf("decision=%v, want escalate", dBroken.Decision)
	}
	_ = day
}
