// PURE per-flow decision engines. Each returns a named-rule-backed decision.
// Nothing here touches the network, filesystem, caller, or an LLM.

import { FlowType, ReasonBucket } from '../flows/types';
import {
  StoppingInput,
  atMaxRetryAttempts,
  atTouchCap,
  exhaustedRetries,
  hasActivePromiseToPay,
  isFraudFlagged,
  isMandateRevoked,
  isRetryable,
  isWithinMandateRetryWindow,
  mandateRetryAttemptAllowed,
  atCheckoutReminderCap,
  isRepeatVisitor,
  cartEligibleForIncentive,
  receivableTier,
  receivableAction,
  atVoiceCallCap,
  isDoNotCall,
  ptpReminderDue,
  ptpDateNotYet,
  ptpMissed,
  ptpNeedsSupervisor,
  successRateBelowThreshold,
} from './rules';
import { EvaluatedStep } from '../flows/types';

export type RuleDecision = { ruleFired: string; decision: 'retry' | 'contact' | 'suppress' | 'escalate' | 'abandon' | 'hold' | 'recover' | 'none' };

// ---------------------------------------------------------------------------
// Flow 3 + 5 base: failed subscription & mandate retry share retry semantics
// ---------------------------------------------------------------------------
function baseRetryDecision(input: StoppingInput): RuleDecision {
  const { reason, currentAttempt, touchesForCustomer, activePromiseToPayDate, now } = input;

  // (b) fraud -> suppress immediately
  if (isFraudFlagged(reason)) return { ruleFired: 'fraud_suppress', decision: 'suppress' };
  // (c) mandate_revoked -> escalate, never retry
  if (isMandateRevoked(reason)) return { ruleFired: 'mandate_revoked_escalate', decision: 'escalate' };
  // (d) active PTP -> suppress until it passes
  if (hasActivePromiseToPay({ activePromiseToPayDate, now })) {
    return { ruleFired: 'promise_to_pay_suppress', decision: 'suppress' };
  }
  // (e) exhausted retries -> escalate (no infinite loop)
  if (atMaxRetryAttempts(currentAttempt) || exhaustedRetries(currentAttempt)) {
    return { ruleFired: 'exhaust_attempts_escalate', decision: 'escalate' };
  }
  // blast radius
  if (atTouchCap(touchesForCustomer)) return { ruleFired: 'max_touches_cap', decision: 'abandon' };
  // retryable?
  if (!isRetryable(reason)) return { ruleFired: 'no_op', decision: 'abandon' };
  return { ruleFired: 'transient_retry', decision: 'retry' };
}

export function decideFailedSubscription(input: StoppingInput): RuleDecision {
  return baseRetryDecision(input);
}

// Flow 5: mandate retry — same base but respects NPCI retry window.
export function decideMandateRetry(input: StoppingInput): RuleDecision {
  const base = baseRetryDecision(input);
  if (base.decision === 'retry') {
    const now = input.now ?? Date.now();
    if (!isWithinMandateRetryWindow(now, input.retryWindow)) {
      return { ruleFired: 'mandate_retry_window', decision: 'hold' };
    }
    if (!mandateRetryAttemptAllowed(input.currentAttempt, now, input.retryWindow)) {
      return { ruleFired: 'mandate_retry_seq', decision: 'hold' };
    }
    return { ruleFired: 'mandate_retry_seq', decision: 'retry' };
  }
  return base;
}

// ---------------------------------------------------------------------------
// Flow 2: checkout abandonment recovery
// ---------------------------------------------------------------------------
export function decideCheckoutAbandonment(input: StoppingInput): RuleDecision {
  const { touchesForCustomer, cartValue, visits, reason } = input;

  // disputed/error buckets that signal a real problem -> don't spam, escalate
  if (reason === 'checkout_error') {
    return { ruleFired: 'checkout_abandon', decision: 'escalate' };
  }
  // Don't chase first-time visitors without evidence of intent (spam guard)
  if (!isRepeatVisitor(visits)) {
    return { ruleFired: 'repeat_visitor_only', decision: 'abandon' };
  }
  // blast radius
  if (atCheckoutReminderCap(touchesForCustomer) || atTouchCap(touchesForCustomer)) {
    return { ruleFired: 'max_touches_cap', decision: 'abandon' };
  }
  // If eligible, offer a cart incentive on FIRST touch to recover.
  if (touchesForCustomer === 0 && cartEligibleForIncentive(cartValue ?? 0)) {
    return { ruleFired: 'cart_incentive', decision: 'contact' };
  }
  return { ruleFired: 'checkout_reminder', decision: 'contact' };
}

// ---------------------------------------------------------------------------
// Flow 4: B2B receivables chaser
// ---------------------------------------------------------------------------
export function decideB2BReceivables(input: StoppingInput): RuleDecision {
  const { reason, overdueDays, touchesForCustomer } = input;

  // Disputed invoice -> hold automated chasing, route to collections human
  if (isMandateRevoked(reason)) return { ruleFired: 'dispute_hold', decision: 'hold' };
  if (reason === 'disputed_receivable') return { ruleFired: 'dispute_hold', decision: 'hold' };

  const days = input.overdueDays ?? 0;
  const tier = receivableTier(days);
  const action = receivableAction(tier);

  // blast radius: don't over-chase a debtor
  if (atTouchCap(touchesForCustomer)) {
    return { ruleFired: 'max_touches_cap', decision: 'abandon' };
  }
  if (action === 'none') return { ruleFired: 'no_op', decision: 'none' };
  if (action === 'remind') return { ruleFired: 'invoice_reminder', decision: 'contact' };
  if (action === 'smtp') return { ruleFired: 'invoice_reminder', decision: 'contact' };
  // dunning / legal -> escalate to collections
  return { ruleFired: 'invoice_escalate_dunning', decision: 'escalate' };
}

// ---------------------------------------------------------------------------
// Flow 1: payment degradation -> root cause -> intervention
// ---------------------------------------------------------------------------
export function decidePaymentDegradation(input: StoppingInput): RuleDecision {
  const { reason } = input;

  if (reason === 'fraud_flagged') return { ruleFired: 'fraud_suppress', decision: 'suppress' };
  if (reason === 'issuer_down') {
    return { ruleFired: 'degradation_escalate', decision: 'escalate' };
  }
  if (successRateBelowThreshold(input.rollingSuccessRate ?? 1)) {
    return { ruleFired: 'degradation_alert', decision: 'contact' };
  }
  return { ruleFired: 'degradation_recover', decision: 'recover' };
}

// ---------------------------------------------------------------------------
// Flow 6: Hinglish voice recovery
// ---------------------------------------------------------------------------
export function decideHinglishVoice(input: StoppingInput): RuleDecision {
  const { reason, touchesForCustomer, now, dncFlag } = input;

  if (isMandateRevoked(reason)) return { ruleFired: 'mandate_revoked_escalate', decision: 'escalate' };
  if (isFraudFlagged(reason)) return { ruleFired: 'fraud_suppress', decision: 'suppress' };
  // Regulatory/TRAI quiet hours + DNC
  if (isDoNotCall({ dncFlag, now })) return { ruleFired: 'voice_do_not_call', decision: 'abandon' };
  if (reason === 'voice_unreachable') return { ruleFired: 'voice_retry', decision: 'contact' };
  if (atVoiceCallCap(touchesForCustomer)) {
    return { ruleFired: 'voice_escalate_human', decision: 'escalate' };
  }
  if (atTouchCap(touchesForCustomer)) return { ruleFired: 'max_touches_cap', decision: 'abandon' };
  return { ruleFired: 'voice_call', decision: 'contact' };
}

// ---------------------------------------------------------------------------
// Flow 7: promise-to-pay tracker
// ---------------------------------------------------------------------------
export function decidePromiseToPay(input: StoppingInput): RuleDecision {
  const { reason, activePromiseToPayDate, now, amount } = input;
  const t = now ?? Date.now();

  if (reason === 'ptp_broken') {
    // Customer broke a PTP -> escalate (human/collections), don't spam
    return { ruleFired: 'ptp_missed_escalate', decision: 'escalate' };
  }
  if (reason === 'ptp_missed') {
    return { ruleFired: 'ptp_missed_escalate', decision: 'escalate' };
  }
  if (reason === 'fraud_flagged') return { ruleFired: 'fraud_suppress', decision: 'suppress' };

  if (activePromiseToPayDate == null) {
    // No PTP on file -> if this is a ptp_committed event lacking a date, hold
    return { ruleFired: 'ptp_schedule', decision: 'hold' };
  }

  // Compliance: large PTPs need supervisor sign-off before automated follow-up
  if (ptpNeedsSupervisor(amount ?? 0)) {
    return { ruleFired: 'ptp_missed_escalate', decision: 'escalate' };
  }

  if (ptpDateNotYet(t, activePromiseToPayDate)) {
    if (ptpReminderDue(t, activePromiseToPayDate)) {
      return { ruleFired: 'ptp_reminder_before', decision: 'contact' };
    }
    // Suppress all other touches until the PTP date passes (rule d)
    return { ruleFired: 'ptp_suppress', decision: 'suppress' };
  }

  if (ptpMissed(t, activePromiseToPayDate)) {
    return { ruleFired: 'ptp_followup', decision: 'contact' };
  }

  return { ruleFired: 'no_op', decision: 'none' };
}

// Dispatch by flow
export function decideForFlow(flow: FlowType, input: StoppingInput): RuleDecision {
  switch (flow) {
    case 'failed_subscription': return decideFailedSubscription(input);
    case 'mandate_retry': return decideMandateRetry(input);
    case 'checkout_abandonment': return decideCheckoutAbandonment(input);
    case 'b2b_receivables': return decideB2BReceivables(input);
    case 'payment_degradation': return decidePaymentDegradation(input);
    case 'hinglish_voice': return decideHinglishVoice(input);
    case 'promise_to_pay': return decidePromiseToPay(input);
  }
}

export type { EvaluatedStep };
