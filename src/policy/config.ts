// Sandbox / backtesting configuration.
//
// A recovery policy has two very different kinds of rule:
//
//   TUNABLE  — business-lever caps a merchant/operator may dial. e.g. retry
//              budget, touch cap, reminder count, mandate window, incentive
//              threshold. You can raise or lower these; recovery trade-offs
//              move with them (more retries => more recovery, more risk).
//
//   LOCKED   — hard safety/compliance invariants that MUST NOT be overridden by
//              any tunable: fraud_flagged, mandate_revoked, do-not-call, and
//              telecom quiet-hours. These are structurally incapable of being
//              turned off here (their predicate functions accept NO tunable).
//
// The backtest engine (sandbox.ts) shifts tunables and watches recovery /
// violation metrics move, while proving the locked rules never budge.

export interface TunableConfig {
  maxRetryAttempts: number; // per-invoice retry budget
  maxTouchesPerCustomer: number; // blast-radius cap on outbound touches
  checkoutReminderCap: number; // max checkout reminders/incentives
  maxVoiceCalls: number; // max voice call attempts
  cartIncentiveThreshold: number; // paise; min cart value to discount
  ptpSupervisorThreshold: number; // paise; PTPs at/above need human sign-off
  mandateWindowDays: number; // NPCI retry window length
  receivableTier2Days: number; // net60 boundary
}

// Defaults mirror today's shipped constants (see decisions/rules.ts).
export const DEFAULT_TUNABLES: TunableConfig = {
  maxRetryAttempts: 3,
  maxTouchesPerCustomer: 3,
  checkoutReminderCap: 2,
  maxVoiceCalls: 2,
  cartIncentiveThreshold: 50000,
  ptpSupervisorThreshold: 2000000,
  mandateWindowDays: 3,
  receivableTier2Days: 60,
};

// The set of rule ids that are permanently locked and can never be overridden.
// The sandbox asserts violations on these stay 0 across every tunable sweep.
export const LOCKED_RULE_IDS = [
  'fraud_suppress', // isFraudFlagged
  'mandate_revoked_escalate', // isMandateRevoked
  'voice_do_not_call', // isDoNotCall
  'quiet_hours', // TRAI 21:00-09:00 IST
] as const;

export type LockedRuleId = (typeof LOCKED_RULE_IDS)[number];
export const TUNABLE_RULE_IDS = [
  'max_retry_attempts',
  'max_touches_cap',
  'checkout_reminder_cap',
  'voice_call_cap',
  'cart_incentive_threshold',
  'ptp_supervisor_threshold',
  'mandate_retry_window',
  'receivable_tier2',
] as const;
export type TunableRuleId = (typeof TUNABLE_RULE_IDS)[number];
