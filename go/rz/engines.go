package rz

// PURE per-flow decision engines. Each returns a named-rule-backed decision.
// Nothing here touches the network, filesystem, caller, or an LLM.

type RuleDecision struct {
	RuleFired RuleId
	Decision  Decision
}

// ---------------------------------------------------------------------------
// Flow 3 + 5 base: failed subscription & mandate retry share retry semantics
// ---------------------------------------------------------------------------
func baseRetryDecision(input StoppingInput) RuleDecision {
	// (b) fraud -> suppress immediately
	if IsFraudFlagged(input.Reason) {
		return RuleDecision{RuleFired: RuleFraudSuppress, Decision: DecisionSuppress}
	}
	// (c) mandate_revoked -> escalate, never retry
	if IsMandateRevoked(input.Reason) {
		return RuleDecision{RuleFired: RuleMandateRevokedEsc, Decision: DecisionEscalate}
	}
	// (d) active PTP -> suppress until it passes
	if HasActivePromiseToPay(input.ActivePromiseToPayDate, input.Now) {
		return RuleDecision{RuleFired: RulePromiseToPaySuppress, Decision: DecisionSuppress}
	}
	// (e) exhausted retries -> escalate (no infinite loop)
	if AtMaxRetryAttempts(input.CurrentAttempt) || ExhaustedRetries(input.CurrentAttempt) {
		return RuleDecision{RuleFired: RuleExhaustAttemptsEscalate, Decision: DecisionEscalate}
	}
	// blast radius
	if AtTouchCap(input.TouchesForCustomer) {
		return RuleDecision{RuleFired: RuleMaxTouchesCap, Decision: DecisionAbandon}
	}
	// retryable?
	if !IsRetryable(input.Reason) {
		return RuleDecision{RuleFired: RuleNoOp, Decision: DecisionAbandon}
	}
	return RuleDecision{RuleFired: RuleTransientRetry, Decision: DecisionRetry}
}

func DecideFailedSubscription(input StoppingInput) RuleDecision {
	return baseRetryDecision(input)
}

// Flow 5: mandate retry — same base but respects NPCI retry window.
func DecideMandateRetry(input StoppingInput) RuleDecision {
	base := baseRetryDecision(input)
	if base.Decision == DecisionRetry {
		now := effectiveNow(input.Now)
		if !IsWithinMandateRetryWindow(now, input.RetryWindow) {
			return RuleDecision{RuleFired: RuleMandateRetryWindow, Decision: DecisionHold}
		}
		if !MandateRetryAttemptAllowed(input.CurrentAttempt, now, input.RetryWindow) {
			return RuleDecision{RuleFired: RuleMandateRetrySeq, Decision: DecisionHold}
		}
		return RuleDecision{RuleFired: RuleMandateRetrySeq, Decision: DecisionRetry}
	}
	return base
}

// ---------------------------------------------------------------------------
// Flow 2: checkout abandonment recovery
// ---------------------------------------------------------------------------
func DecideCheckoutAbandonment(input StoppingInput) RuleDecision {
	// disputed/error buckets that signal a real problem -> don't spam, escalate
	if input.Reason == ReasonCheckoutError {
		return RuleDecision{RuleFired: RuleCheckoutAbandon, Decision: DecisionEscalate}
	}
	// Don't chase first-time visitors without evidence of intent (spam guard)
	if !IsRepeatVisitor(input.Visits) {
		return RuleDecision{RuleFired: RuleRepeatVisitorOnly, Decision: DecisionAbandon}
	}
	// blast radius
	if AtCheckoutReminderCap(input.TouchesForCustomer) || AtTouchCap(input.TouchesForCustomer) {
		return RuleDecision{RuleFired: RuleMaxTouchesCap, Decision: DecisionAbandon}
	}
	// If eligible, offer a cart incentive on FIRST touch to recover.
	if input.TouchesForCustomer == 0 && CartEligibleForIncentive(input.CartValue) {
		return RuleDecision{RuleFired: RuleCartIncentive, Decision: DecisionContact}
	}
	return RuleDecision{RuleFired: RuleCheckoutReminder, Decision: DecisionContact}
}

// ---------------------------------------------------------------------------
// Flow 4: B2B receivables chaser
// ---------------------------------------------------------------------------
func DecideB2BReceivables(input StoppingInput) RuleDecision {
	// Disputed invoice -> hold automated chasing, route to collections human
	if IsMandateRevoked(input.Reason) {
		return RuleDecision{RuleFired: RuleDisputeHold, Decision: DecisionHold}
	}
	if input.Reason == ReasonDisputedReceivable {
		return RuleDecision{RuleFired: RuleDisputeHold, Decision: DecisionHold}
	}

	days := input.OverdueDays
	if days == 0 {
		days = 0
	}
	tier := ReceivableTier(days)
	action := ReceivableAction(tier)

	// blast radius: don't over-chase a debtor
	if AtTouchCap(input.TouchesForCustomer) {
		return RuleDecision{RuleFired: RuleMaxTouchesCap, Decision: DecisionAbandon}
	}
	if action == "none" {
		return RuleDecision{RuleFired: RuleNoOp, Decision: DecisionNone}
	}
	if action == "remind" || action == "smtp" {
		return RuleDecision{RuleFired: RuleInvoiceReminder, Decision: DecisionContact}
	}
	// dunning / legal -> escalate to collections
	return RuleDecision{RuleFired: RuleInvoiceEscalateDun, Decision: DecisionEscalate}
}

// ---------------------------------------------------------------------------
// Flow 1: payment degradation -> root cause -> intervention
// ---------------------------------------------------------------------------
func DecidePaymentDegradation(input StoppingInput) RuleDecision {
	if input.Reason == ReasonFraudFlagged {
		return RuleDecision{RuleFired: RuleFraudSuppress, Decision: DecisionSuppress}
	}
	if input.Reason == ReasonIssuerDown {
		return RuleDecision{RuleFired: RuleDegradationEscalate, Decision: DecisionEscalate}
	}
	rate := input.RollingSuccessRate
	if rate == 0 {
		rate = 1
	}
	if SuccessRateBelowThreshold(rate) {
		return RuleDecision{RuleFired: RuleDegradationAlert, Decision: DecisionContact}
	}
	return RuleDecision{RuleFired: RuleDegradationRecover, Decision: DecisionRecover}
}

// ---------------------------------------------------------------------------
// Flow 6: Hinglish voice recovery
// ---------------------------------------------------------------------------
func DecideHinglishVoice(input StoppingInput) RuleDecision {
	if IsMandateRevoked(input.Reason) {
		return RuleDecision{RuleFired: RuleMandateRevokedEsc, Decision: DecisionEscalate}
	}
	if IsFraudFlagged(input.Reason) {
		return RuleDecision{RuleFired: RuleFraudSuppress, Decision: DecisionSuppress}
	}
	// Regulatory/TRAI quiet hours + DNC
	if IsDoNotCall(input.DNCFlag, effectiveNow(input.Now)) {
		return RuleDecision{RuleFired: RuleVoiceDoNotCall, Decision: DecisionAbandon}
	}
	if input.Reason == ReasonVoiceUnreachable {
		return RuleDecision{RuleFired: RuleVoiceRetry, Decision: DecisionContact}
	}
	if AtVoiceCallCap(input.TouchesForCustomer) {
		return RuleDecision{RuleFired: RuleVoiceEscalateHuman, Decision: DecisionEscalate}
	}
	if AtTouchCap(input.TouchesForCustomer) {
		return RuleDecision{RuleFired: RuleMaxTouchesCap, Decision: DecisionAbandon}
	}
	return RuleDecision{RuleFired: RuleVoiceCall, Decision: DecisionContact}
}

// ---------------------------------------------------------------------------
// Flow 7: promise-to-pay tracker
// ---------------------------------------------------------------------------
func DecidePromiseToPay(input StoppingInput) RuleDecision {
	t := effectiveNow(input.Now)

	if input.Reason == ReasonPtpBroken || input.Reason == ReasonPtpMissed {
		// Customer broke/missed a PTP -> escalate (human/collections), don't spam
		return RuleDecision{RuleFired: RulePtpMissedEscalate, Decision: DecisionEscalate}
	}
	if input.Reason == ReasonFraudFlagged {
		return RuleDecision{RuleFired: RuleFraudSuppress, Decision: DecisionSuppress}
	}

	if input.ActivePromiseToPayDate == nil {
		// No PTP on file -> if this is a ptp_committed event lacking a date, hold
		return RuleDecision{RuleFired: RulePtpSchedule, Decision: DecisionHold}
	}

	ptpDate := *input.ActivePromiseToPayDate

	// Compliance: large PTPs need supervisor sign-off before automated follow-up
	if PtpNeedsSupervisor(input.Amount) {
		return RuleDecision{RuleFired: RulePtpMissedEscalate, Decision: DecisionEscalate}
	}

	if PtpDateNotYet(t, ptpDate) {
		if PtpReminderDue(t, ptpDate) {
			return RuleDecision{RuleFired: RulePtpReminderBefore, Decision: DecisionContact}
		}
		// Suppress all other touches until the PTP date passes (rule d)
		return RuleDecision{RuleFired: RulePtpSuppress, Decision: DecisionSuppress}
	}

	if PtpMissed(t, ptpDate) {
		return RuleDecision{RuleFired: RulePtpFollowup, Decision: DecisionContact}
	}

	return RuleDecision{RuleFired: RuleNoOp, Decision: DecisionNone}
}

// DecideForFlow dispatches by flow.
func DecideForFlow(flow FlowType, input StoppingInput) RuleDecision {
	switch flow {
	case FlowFailedSubscription:
		return DecideFailedSubscription(input)
	case FlowMandateRetry:
		return DecideMandateRetry(input)
	case FlowCheckoutAbandonment:
		return DecideCheckoutAbandonment(input)
	case FlowB2BReceivables:
		return DecideB2BReceivables(input)
	case FlowPaymentDegradation:
		return DecidePaymentDegradation(input)
	case FlowHinglishVoice:
		return DecideHinglishVoice(input)
	case FlowPromiseToPay:
		return DecidePromiseToPay(input)
	}
	return RuleDecision{RuleFired: RuleNoOp, Decision: DecisionNone}
}
