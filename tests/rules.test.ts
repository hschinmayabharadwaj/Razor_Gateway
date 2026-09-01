import { describe, it, expect } from 'vitest';
import {
  MAX_RETRY_ATTEMPTS,
  MAX_OUTBOUND_TOUCHES_PER_CUSTOMER,
  atMaxRetryAttempts,
  isFraudFlagged,
  isMandateRevoked,
  exhaustedRetries,
  hasActivePromiseToPay,
  atTouchCap,
  isRetryable,
  isWithinMandateRetryWindow,
  mandateRetryAttemptAllowed,
  receivableTier,
  receivableAction,
  atCheckoutReminderCap,
  isRepeatVisitor,
  cartEligibleForIncentive,
  atVoiceCallCap,
  isDoNotCall,
  ptpReminderDue,
  ptpDateNotYet,
  ptpMissed,
  ptpNeedsSupervisor,
  successRateBelowThreshold,
} from '../src/decisions/rules';
import {
  decideFailedSubscription,
  decideMandateRetry,
  decideCheckoutAbandonment,
  decideB2BReceivables,
  decidePaymentDegradation,
  decideHinglishVoice,
  decidePromiseToPay,
} from '../src/decisions/engines';

// ---------------------------------------------------------------------------
// Rule (a): max_retry_attempts = 3 per invoice (failed_subscription)
// ---------------------------------------------------------------------------
describe('Rule (a): max_retry_attempts = 3 per invoice', () => {
  it('returns false below 3, true at 3', () => {
    expect(atMaxRetryAttempts(0)).toBe(false);
    expect(atMaxRetryAttempts(2)).toBe(false);
    expect(atMaxRetryAttempts(3)).toBe(true);
  });
  it('constant is exactly 3', () => {
    expect(MAX_RETRY_ATTEMPTS()).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Rule (b): NEVER retry if fraud_flagged -> suppressed
// ---------------------------------------------------------------------------
describe('Rule (b): NEVER retry if fraud_flagged -> suppressed', () => {
  it('flags fraud_flagged', () => {
    expect(isFraudFlagged('fraud_flagged')).toBe(true);
    expect(isFraudFlagged('insufficient_funds')).toBe(false);
  });
  it('engine suppresses fraud_flagged even at attempt 0', () => {
    const d = decideFailedSubscription({ reason: 'fraud_flagged', currentAttempt: 0, touchesForCustomer: 0 });
    expect(d).toEqual({ ruleFired: 'fraud_suppress', decision: 'suppress' });
  });
});

// ---------------------------------------------------------------------------
// Rule (c): NEVER retry if mandate_revoked -> escalate, no automated retry
// ---------------------------------------------------------------------------
describe('Rule (c): NEVER retry if mandate_revoked -> escalate', () => {
  it('flags mandate_revoked', () => {
    expect(isMandateRevoked('mandate_revoked')).toBe(true);
  });
  it('engine escalates mandate_revoked, never retries', () => {
    const d = decideFailedSubscription({ reason: 'mandate_revoked', currentAttempt: 0, touchesForCustomer: 0 });
    expect(d).toEqual({ ruleFired: 'mandate_revoked_escalate', decision: 'escalate' });
  });
});

// ---------------------------------------------------------------------------
// Rule (d): active promise-to-pay suppresses other touches (subscription)
// ---------------------------------------------------------------------------
describe('Rule (d): active promise-to-pay suppresses retries', () => {
  const future = Date.now() + 100000;
  const past = Date.now() - 100000;
  it('suppresses when promise date is in the future', () => {
    const d = decideFailedSubscription({ reason: 'insufficient_funds', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: future });
    expect(d).toEqual({ ruleFired: 'promise_to_pay_suppress', decision: 'suppress' });
  });
  it('allows retry when promise date is in the past', () => {
    const d = decideFailedSubscription({ reason: 'insufficient_funds', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: past });
    expect(d.decision).toBe('retry');
  });
  it('hasActivePromiseToPay handles no date', () => {
    expect(hasActivePromiseToPay({})).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Rule (e): after 3 failed retries -> escalate, no infinite loop
// ---------------------------------------------------------------------------
describe('Rule (e): after 3 failed retries -> escalate', () => {
  it('escalates at attempt 3', () => {
    const d = decideFailedSubscription({ reason: 'insufficient_funds', currentAttempt: 3, touchesForCustomer: 0 });
    expect(d).toEqual({ ruleFired: 'exhaust_attempts_escalate', decision: 'escalate' });
  });
  it('exhaustedRetries true at 3', () => {
    expect(exhaustedRetries(3)).toBe(true);
    expect(exhaustedRetries(2)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Blast radius: max outbound touches per customer
// ---------------------------------------------------------------------------
describe('Blast radius: max outbound touches per customer', () => {
  it('abandons at touch cap', () => {
    const d = decideFailedSubscription({ reason: 'insufficient_funds', currentAttempt: 0, touchesForCustomer: 3 });
    expect(d).toEqual({ ruleFired: 'max_touches_cap', decision: 'abandon' });
  });
  it('constant is exactly 3', () => {
    expect(MAX_OUTBOUND_TOUCHES_PER_CUSTOMER()).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Retryable taxonomy
// ---------------------------------------------------------------------------
describe('Retryable taxonomy', () => {
  it('allows retry for retryable buckets', () => {
    expect(isRetryable('insufficient_funds')).toBe(true);
    expect(isRetryable('card_expired')).toBe(true);
    expect(isRetryable('bank_declined_transient')).toBe(true);
    expect(isRetryable('auth_3ds_abandoned')).toBe(true);
  });
  it('refuses retry for non-retryable buckets', () => {
    expect(isRetryable('fraud_flagged')).toBe(false);
    expect(isRetryable('mandate_revoked')).toBe(false);
  });
  it('engine returns retry for a retryable reason within budget', () => {
    const d = decideFailedSubscription({ reason: 'bank_declined_transient', currentAttempt: 0, touchesForCustomer: 0 });
    expect(d.decision).toBe('retry');
  });
});

// ---------------------------------------------------------------------------
// Flow 5: mandate retry — NPCI retry-window sequencing (India-specific)
// ---------------------------------------------------------------------------
describe('Mandate retry: NPCI retry-window sequencing (India-specific)', () => {
  const start = Date.UTC(2026, 8, 1);
  const window = { start, end: start + 3 * 86400000 };

  it('isWithinMandateRetryWindow true inside, false outside', () => {
    expect(isWithinMandateRetryWindow(start + 86400000, window)).toBe(true);
    expect(isWithinMandateRetryWindow(start - 1, window)).toBe(false);
    expect(isWithinMandateRetryWindow(window.end + 1, window)).toBe(false);
  });
  it('mandateRetryAttemptAllowed respects day-offset bound', () => {
    expect(mandateRetryAttemptAllowed(0, start, window)).toBe(true);
    expect(mandateRetryAttemptAllowed(1, start + 86400000, window)).toBe(true);
    expect(mandateRetryAttemptAllowed(3, start + 3 * 86400000, window)).toBe(false);
  });
  it('engine holds when outside retry window', () => {
    const d = decideMandateRetry({ reason: 'insufficient_funds', currentAttempt: 0, touchesForCustomer: 0, now: window.end + 86400000, retryWindow: window });
    expect(d).toEqual({ ruleFired: 'mandate_retry_window', decision: 'hold' });
  });
  it('engine sequences within window', () => {
    const d = decideMandateRetry({ reason: 'insufficient_funds', currentAttempt: 0, touchesForCustomer: 0, now: start, retryWindow: window });
    expect(d.decision).toBe('retry');
  });
});

// ---------------------------------------------------------------------------
// Flow 2: checkout abandonment
// ---------------------------------------------------------------------------
describe('Checkout abandonment recovery (cost-aware + spam guard)', () => {
  it('only recovers repeat visitors', () => {
    expect(isRepeatVisitor(1)).toBe(false);
    expect(isRepeatVisitor(2)).toBe(true);
    expect(decideCheckoutAbandonment({ reason: 'payment_step_abandoned', currentAttempt: 0, touchesForCustomer: 0, visits: 1, cartValue: 100000 }).decision).toBe('abandon');
  });
  it('offers incentive only for carts above threshold', () => {
    expect(cartEligibleForIncentive(100000)).toBe(true);
    expect(cartEligibleForIncentive(10000)).toBe(false);
  });
  it('caps at 2 reminders', () => {
    expect(atCheckoutReminderCap(2)).toBe(true);
    expect(decideCheckoutAbandonment({ reason: 'payment_step_abandoned', currentAttempt: 0, touchesForCustomer: 2, visits: 3, cartValue: 100000 }).decision).toBe('abandon');
  });
  it('escalates checkout_error instead of spamming', () => {
    const d = decideCheckoutAbandonment({ reason: 'checkout_error', currentAttempt: 0, touchesForCustomer: 0, visits: 3, cartValue: 100000 });
    expect(d.decision).toBe('escalate');
  });
});

// ---------------------------------------------------------------------------
// Flow 4: B2B receivables
// ---------------------------------------------------------------------------
describe('B2B receivables chaser (tiered dunning)', () => {
  it('no action under net30', () => {
    expect(receivableAction(receivableTier(10))).toBe('none');
  });
  it('remind at tier 1, smtp at tier 2', () => {
    expect(receivableAction(receivableTier(40))).toBe('remind');
    expect(receivableAction(receivableTier(75))).toBe('smtp');
  });
  it('escalates to collections for tier 3', () => {
    expect(receivableAction(receivableTier(130))).toBe('dunning');
    expect(decideB2BReceivables({ reason: 'overdue_net60', currentAttempt: 0, touchesForCustomer: 0, overdueDays: 130 }).decision).toBe('escalate');
  });
  it('holds disputed receivables', () => {
    const d = decideB2BReceivables({ reason: 'disputed_receivable', currentAttempt: 0, touchesForCustomer: 0, overdueDays: 40 });
    expect(d).toEqual({ ruleFired: 'dispute_hold', decision: 'hold' });
  });
});

// ---------------------------------------------------------------------------
// Flow 1: payment degradation
// ---------------------------------------------------------------------------
describe('Payment degradation detection', () => {
  it('alerts when success rate below threshold', () => {
    expect(successRateBelowThreshold(0.8)).toBe(true);
    expect(successRateBelowThreshold(0.98)).toBe(false);
  });
  it('escalates issuer-down', () => {
    const d = decidePaymentDegradation({ reason: 'issuer_down', currentAttempt: 0, touchesForCustomer: 0 });
    expect(d).toEqual({ ruleFired: 'degradation_escalate', decision: 'escalate' });
  });
});

// ---------------------------------------------------------------------------
// Flow 6: Hinglish voice recovery (regulatory quiet hours + DNC)
// ---------------------------------------------------------------------------
describe('Hinglish voice recovery (TRAI quiet hours + DNC)', () => {
  it('respects DNC flag', () => {
    expect(isDoNotCall({ dncFlag: true, now: Date.UTC(2026, 8, 1, 14) })).toBe(true);
  });
  it('stops calls during quiet hours (21:00-09:00)', () => {
    expect(isDoNotCall({ now: Date.UTC(2026, 8, 1, 22) })).toBe(true);
    expect(isDoNotCall({ now: Date.UTC(2026, 8, 1, 14) })).toBe(false);
  });
  it('caps voice calls at 2 then escalates to human', () => {
    expect(atVoiceCallCap(2)).toBe(true);
    const d = decideHinglishVoice({ reason: 'voice_missed_call', currentAttempt: 0, touchesForCustomer: 2, dncFlag: false, now: Date.UTC(2026, 8, 1, 14) });
    expect(d).toEqual({ ruleFired: 'voice_escalate_human', decision: 'escalate' });
  });
  it('abandons on DNC (regulatory)', () => {
    const d = decideHinglishVoice({ reason: 'voice_missed_call', currentAttempt: 0, touchesForCustomer: 0, dncFlag: true, now: Date.UTC(2026, 8, 1, 14) });
    expect(d).toEqual({ ruleFired: 'voice_do_not_call', decision: 'abandon' });
  });
});

// ---------------------------------------------------------------------------
// Flow 7: Promise-to-pay tracker
// ---------------------------------------------------------------------------
describe('Promise-to-pay tracker (compliance + suppression)', () => {
  const now = Date.UTC(2026, 8, 15);
  const futurePtp = now + 2 * 86400000;
  const pastPtp = now - 86400000;

  it('suppresses all touches until PTP date passes', () => {
    const d = decidePromiseToPay({ reason: 'ptp_committed', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: futurePtp, now, amount: 100000 });
    expect(d).toEqual({ ruleFired: 'ptp_suppress', decision: 'suppress' });
  });
  it('sends reminder 24h before PTP date', () => {
    expect(ptpReminderDue(futurePtp - 3600000, futurePtp)).toBe(true);
    const d = decidePromiseToPay({ reason: 'ptp_committed', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: futurePtp, now: futurePtp - 3600000, amount: 100000 });
    expect(d).toEqual({ ruleFired: 'ptp_reminder_before', decision: 'contact' });
  });
  it('follows up after PTP date', () => {
    const d = decidePromiseToPay({ reason: 'ptp_committed', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: pastPtp, now, amount: 100000 });
    expect(d.decision).toBe('contact');
  });
  it('esc for large PTPs needing supervisor (compliance)', () => {
    const big = decidePromiseToPay({ reason: 'ptp_committed', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: futurePtp, now, amount: 5000000 });
    expect(big.decision).toBe('escalate');
  });
  it('escalates broken/missed PTP', () => {
    expect(ptpMissed(now, pastPtp)).toBe(true);
    expect(ptpNeedsSupervisor(5000000)).toBe(true);
    expect(decidePromiseToPay({ reason: 'ptp_broken', currentAttempt: 0, touchesForCustomer: 0, activePromiseToPayDate: pastPtp, now, amount: 100000 }).decision).toBe('escalate');
  });
});
