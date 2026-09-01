import { describe, it, expect } from 'vitest';
import { NaiveTouch } from '../src/policy/naivePolicy';
import { countComplianceViolations } from '../src/policy/compare';
import { GENESIS_HASH } from '../src/audit/chain';

function touch(over: Partial<NaiveTouch> = {}): NaiveTouch {
  return {
    eventId: 'e',
    flow: 'failed_subscription',
    customerId: 'c',
    reason: 'insufficient_funds',
    attempt: 0,
    touchesForCustomer: 0,
    channel: 'api',
    now: Date.UTC(2026, 8, 1, 14, 30),
    dncFlag: false,
    activePromiseToPayDate: null,
    ...over,
  };
}

describe('countComplianceViolations re-checks NAIVE actions against REAL rules', () => {
  it('flags retrying a fraud_flagged event', () => {
    const v = countComplianceViolations([touch({ reason: 'fraud_flagged' })]);
    expect(v.fraud_retries).toBe(1);
    expect(v.total).toBe(1);
  });
  it('flags retrying a mandate_revoked event', () => {
    const v = countComplianceViolations([touch({ reason: 'mandate_revoked' })]);
    expect(v.mandate_retries).toBe(1);
    expect(v.total).toBe(1);
  });
  it('flags a voice call during TRAI quiet hours', () => {
    const v = countComplianceViolations([touch({ channel: 'voice', now: Date.UTC(2026, 8, 1, 22, 0) })]);
    expect(v.quiet_hour_calls).toBe(1);
    expect(v.total).toBe(1);
  });
  it('flags a DNC breach', () => {
    const v = countComplianceViolations([touch({ channel: 'voice', dncFlag: true, now: Date.UTC(2026, 8, 1, 14, 0) })]);
    expect(v.dnc_breaches).toBe(1);
    expect(v.total).toBe(1);
  });
  it('flags a per-customer touch-cap breach', () => {
    const v = countComplianceViolations([touch({ touchesForCustomer: 3 })]);
    expect(v.touch_cap_breaches).toBe(1);
    expect(v.total).toBe(1);
  });
  it('flags an over-budget retry (beyond MAX_RETRY_ATTEMPTS=3)', () => {
    const v = countComplianceViolations([touch({ attempt: 3 })]);
    expect(v.retry_budget_breaches).toBe(1);
    expect(v.total).toBe(1);
  });
  it('flags touching a customer with an active promise-to-pay', () => {
    const v = countComplianceViolations([touch({ activePromiseToPayDate: Date.UTC(2026, 8, 5, 0, 0), now: Date.UTC(2026, 8, 1, 14, 0) })]);
    expect(v.ptp_suppression_breaches).toBe(1);
    expect(v.total).toBe(1);
  });
  it('counts unique unsafe ACTIONS (one touch violating multiple rules = 1 action)', () => {
    // a single touch that retries a fraud event at attempt 10 over the touch cap
    const v = countComplianceViolations([touch({ reason: 'fraud_flagged', attempt: 9, touchesForCustomer: 3 })]);
    expect(v.fraud_retries).toBe(1);
    expect(v.retry_budget_breaches).toBe(1);
    expect(v.touch_cap_breaches).toBe(1);
    expect(v.total).toBe(1); // still ONE unsafe action
  });
});

describe('GENESIS_HASH consistency', () => {
  it('is 64 zero chars', () => {
    expect(GENESIS_HASH).toBe('0'.repeat(64));
  });
});
