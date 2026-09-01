// NAMED STOPPING RULES across all flows.
// Every rule is a small, pure, individually testable function. The decision
// engines compose these; no LLM ever runs them. Money-moving / stopping
// decisions are always traceable to one of these named functions.
//
// Tunability: business-lever caps (retry budget, touch cap, reminder cap, voice
// cap, incentive threshold, supervisor threshold, mandate window, receivable
// boundary) are read from a mutable config so a backtest can sweep them and
// watch recovery/violation metrics move. The LOCKED safety/compliance rules
// (fraud, mandate_revoked, DNC, quiet-hours) accept no tunable and therefore
// can never be disabled — that property is what the sandbox demonstrates.

import { ReasonBucket } from '../flows/types';
import { DEFAULT_TUNABLES, TunableConfig } from '../policy/config';

// Current tunable values (mutable for backtests). Defaults == shipped constants.
let tunables: TunableConfig = { ...DEFAULT_TUNABLES };
export function setTunables(t: Partial<TunableConfig>): TunableConfig {
  tunables = { ...tunables, ...t };
  return tunables;
}
export function resetTunables(): TunableConfig {
  tunables = { ...DEFAULT_TUNABLES };
  return tunables;
}
export function getTunables(): TunableConfig {
  return { ...tunables };
}

// ---------- Generic blast-radius caps ----------
export function MAX_TOUCHES_PER_CUSTOMER(): number { return tunables.maxTouchesPerCustomer; }
export function MAX_OUTBOUND_TOUCHES_PER_CUSTOMER(): number { return tunables.maxTouchesPerCustomer; }
export function atTouchCap(existingTouches: number): boolean {
  return existingTouches >= tunables.maxTouchesPerCustomer;
}

// ---------- failed_subscription / mandate_retry: retry budget ----------
export function MAX_RETRY_ATTEMPTS(): number { return tunables.maxRetryAttempts; }
export function atMaxRetryAttempts(currentAttempt: number): boolean {
  return currentAttempt >= tunables.maxRetryAttempts;
}
export function exhaustedRetries(currentAttempt: number): boolean {
  return currentAttempt >= tunables.maxRetryAttempts;
}

// (b) never retry fraud_flagged
export function isFraudFlagged(reason: ReasonBucket): boolean {
  return reason === 'fraud_flagged';
}

// (c) never retry mandate_revoked -> escalate
export function isMandateRevoked(reason: ReasonBucket): boolean {
  return reason === 'mandate_revoked';
}

// (d) active promise-to-pay date in the future -> suppress touches
export interface PromiseToPayContext {
  activePromiseToPayDate?: number | null;
  now?: number;
}
export function hasActivePromiseToPay(ctx: PromiseToPayContext): boolean {
  if (ctx.activePromiseToPayDate == null) return false;
  const now = ctx.now ?? Date.now();
  return ctx.activePromiseToPayDate > now;
}

// Retryable buckets for failed_subscription
const RETRYABLE: ReadonlySet<ReasonBucket> = new Set<ReasonBucket>([
  'insufficient_funds',
  'card_expired',
  'bank_declined_transient',
  'auth_3ds_abandoned',
]);
export function isRetryable(reason: ReasonBucket): boolean {
  return RETRYABLE.has(reason);
}

export const MAX_BATCH_ATTEMPTS = () => 60 * tunables.maxRetryAttempts;

// ---------- mandate_retry: NPCI / UPI Autopay retry-window constraints ----------
// UPI Autopay retry cadence is bounded by NPCI rules (first attempt on due date,
// re-attempts within the mandate's retry window; typically a few days window).
// We encode the retry sequence explicitly rather than retrying every 3 days,
// with the window length configurable as a tunable (mandateWindowDays).
export function MANDATE_RETRY_SEQUENCE_MS(): number[] {
  const days = Math.max(1, tunables.mandateWindowDays);
  const seq: number[] = [0]; // attempt 0: on due date
  for (let d = 1; d < days; d++) seq.push(d * 24 * 3600 * 1000);
  return seq;
}
export function isWithinMandateRetryWindow(
  now: number,
  window: { start: number; end: number } | undefined,
): boolean {
  if (!window) return false;
  return now >= window.start && now <= window.end;
}
export function mandateRetryAttemptAllowed(
  currentAttempt: number,
  now: number,
  window: { start: number; end: number } | undefined,
): boolean {
  if (!window) return false;
  const dayOffset = Math.floor((now - window.start) / (24 * 3600 * 1000));
  const seq = MANDATE_RETRY_SEQUENCE_MS();
  return (
    dayOffset >= 0 &&
    dayOffset < seq.length &&
    currentAttempt <= dayOffset
  );
}

// ---------- checkout_abandonment ----------
export const CHECKOUT_REMINDER_MS = 30 * 60 * 1000; // 30 min
export function CHECKOUT_ABANDON_REMINDERS(): number { return tunables.checkoutReminderCap; }
export function atCheckoutReminderCap(remindersSent: number): boolean {
  return remindersSent >= tunables.checkoutReminderCap;
}
// Only recover checkout for repeat/did-not-quite-finish visitors to avoid spam.
export function isRepeatVisitor(visits: number | undefined): boolean {
  return (visits ?? 1) >= 2;
}
// Incentive only if cart value above a threshold (cost-aware: don't discount junk carts)
export function CART_INCENTIVE_THRESHOLD(): number { return tunables.cartIncentiveThreshold; }
export function cartEligibleForIncentive(cartValue: number): boolean {
  return cartValue >= tunables.cartIncentiveThreshold;
}

// ---------- b2b_receivables ----------
export const RECEIVABLE_TIER1_DAYS = 30; // net30
export function receivableTier(overdueDays: number): 0 | 1 | 2 | 3 {
  const t2 = tunables.receivableTier2Days;
  if (overdueDays < RECEIVABLE_TIER1_DAYS) return 0;
  if (overdueDays < t2) return 1;
  return overdueDays < t2 * 2 ? 2 : 3;
}
// Dunning escalation ladder
export function receivableAction(tier: number): 'none' | 'remind' | 'smtp' | 'dunning' | 'legal' {
  switch (tier) {
    case 0: return 'none';
    case 1: return 'remind';
    case 2: return 'smtp';
    default: return 'dunning';
  }
}
export function isDisputed(reason: ReasonBucket): boolean {
  return reason === 'disputed_receivable';
}

// ---------- payment_degradation ----------
export const DEGRADATION_SUCCESS_RATE_THRESHOLD = 0.85; // < 85% triggers alert
export const DEGRADATION_LATENCY_MS_THRESHOLD = 2000;
export function successRateBelowThreshold(rollingRate: number): boolean {
  return rollingRate < DEGRADATION_SUCCESS_RATE_THRESHOLD;
}

// ---------- hinglish_voice ----------
export function MAX_VOICE_CALLS(): number { return tunables.maxVoiceCalls; }
export function atVoiceCallCap(callsMade: number): boolean {
  return callsMade >= tunables.maxVoiceCalls;
}
export function isDoNotCall(ctx: { dncFlag?: boolean; now?: number; window?: { start: number; end: number } }): boolean {
  if (ctx.dncFlag) return true;
  if (!ctx.now) return false;
  // Telecom regulator quiet hours 21:00–09:00 IST. Compute hour in IST
  // (UTC+5:30) deterministically regardless of machine timezone.
  const istMs = ctx.now + 5.5 * 3600 * 1000;
  const hour = new Date(istMs).getUTCHours();
  return hour >= 21 || hour < 9;
}

// ---------- promise_to_pay ----------
export const PTP_REMINDER_BEFORE_MS = 24 * 3600 * 1000; // remind 24h before
export function ptpReminderDue(now: number, ptpDate: number): boolean {
  return now >= ptpDate - PTP_REMINDER_BEFORE_MS && now < ptpDate;
}
export function ptpDateNotYet(now: number, ptpDate: number): boolean {
  return now < ptpDate;
}
export function ptpMissed(now: number, ptpDate: number): boolean {
  return now > ptpDate;
}
export function ptpNeedsSupervisor(amount: number): boolean {
  return amount >= tunables.ptpSupervisorThreshold; // configurable (compliance ceiling)
}

// ---------- Decision input/context shared ----------
export interface StoppingInput {
  reason: ReasonBucket;
  currentAttempt: number; // 0-based for this recovery cycle
  touchesForCustomer: number;
  activePromiseToPayDate?: number | null;
  overdueDays?: number;
  now?: number;
  retryWindow?: { start: number; end: number };
  dncFlag?: boolean;
  cartValue?: number;
  visits?: number;
  rollingSuccessRate?: number;
  amount?: number; // minor unit
}
