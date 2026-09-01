// Unified multi-flow domain model for the Revenue Recovery Agent.
// This extends the original subscription-only agent into 7 recovery flows.
// Core ideologies preserved: deterministic decisions, audit-first, narrow taxonomy,
// state machine not chatbot, cost-aware, India-specific.

export type FlowType =
  | 'payment_degradation' // 1. payment success rate dropping -> root cause -> recovery
  | 'checkout_abandonment' // 2. cart/checkout dropped -> recover with reminder + incentive
  | 'failed_subscription' // 3. subscription.charged.failed -> retry/escalate
  | 'b2b_receivables' // 4. overdue invoice -> chaser cadence
  | 'mandate_retry' // 5. NPCI/UPI Autopay mandate retry sequencing
  | 'hinglish_voice' // 6. phone call recovery in Hinglish
  | 'promise_to_pay'; // 7. track PTP date, suppress until it passes, then follow up

export const FLOW_TYPES: readonly FlowType[] = [
  'payment_degradation',
  'checkout_abandonment',
  'failed_subscription',
  'b2b_receivables',
  'mandate_retry',
  'hinglish_voice',
  'promise_to_pay',
];

// Narrow taxonomy per flow. Each flow only classifies into its own small set.
export type ReasonBucket =
  // payment/flows shared buckets
  | 'insufficient_funds'
  | 'card_expired'
  | 'mandate_revoked'
  | 'bank_declined_transient'
  | 'auth_3ds_abandoned'
  | 'fraud_flagged'
  // payment_degradation
  | 'success_rate_drop'
  | 'latency_spike'
  | 'issuer_down'
  // checkout_abandonment
  | 'price_mismatch'
  | 'payment_step_abandoned'
  | 'address_abandoned'
  | 'slow_checkout'
  | 'checkout_error'
  // b2b_receivables
  | 'overdue_net30'
  | 'overdue_net60'
  | 'disputed_receivable'
  // mandate_retry
  | 'mandate_insufficient'
  | 'mandate_bank_down'
  | 'mandate_auth_pending'
  // hinglish_voice
  | 'voice_missed_call'
  | 'voice_asked_call_back'
  | 'voice_unreachable'
  // promise_to_pay
  | 'ptp_committed'
  | 'ptp_missed'
  | 'ptp_broken';

// States: unified across all flows, but only a subset applies per flow.
export type AgentState =
  | 'detected'
  | 'diagnosed'
  | 'retry_scheduled'
  | 'retrying'
  | 'contact_scheduled'
  | 'contacting'
  | 'waiting_on_ptp'
  | 'recovered'
  | 'escalated'
  | 'abandoned'
  | 'suppressed';

export const TERMINAL_STATES: ReadonlySet<AgentState> = new Set<AgentState>([
  'recovered',
  'escalated',
  'abandoned',
  'suppressed',
]);

export type Actor = 'policy_engine' | 'llm_copy' | 'human' | 'dialer';

// Named rule identifiers (money-moving / stopping rules are all named & testable).
export type RuleId =
  // generic
  | 'no_op'
  | 'recovered'
  | 'escalate_manual'
  | 'abandon_manual'
  | 'max_touches_cap'
  // failed_subscription / mandate_retry
  | 'max_retry_attempts'
  | 'fraud_suppress'
  | 'mandate_revoked_escalate'
  | 'promise_to_pay_suppress'
  | 'schedule_retry'
  | 'execute_retry'
  | 'transient_retry'
  | 'exhaust_attempts_escalate'
  | 'mandate_retry_window'
  | 'mandate_retry_seq'
  // checkout_abandonment
  | 'checkout_reminder'
  | 'cart_incentive'
  | 'checkout_recover'
  | 'checkout_abandon'
  | 'repeat_visitor_only'
  // b2b_receivables
  | 'receivable_tier'
  | 'invoice_reminder'
  | 'invoice_escalate_dunning'
  | 'dispute_hold'
  // payment_degradation
  | 'degradation_alert'
  | 'degradation_recover'
  | 'degradation_escalate'
  // hinglish_voice
  | 'voice_call'
  | 'voice_retry'
  | 'voice_escalate_human'
  | 'voice_do_not_call'
  // promise_to_pay
  | 'ptp_schedule'
  | 'ptp_suppress'
  | 'ptp_followup'
  | 'ptp_reminder_before'
  | 'ptp_missed_escalate'
  | 'batch_max_attempts';

export type Decision =
  | 'retry'
  | 'contact'
  | 'recover'
  | 'escalate'
  | 'suppress'
  | 'abandon'
  | 'hold'
  | 'none';

export interface AuditEntry {
  eventId: string;
  timestamp: string;
  flow: FlowType;
  reasonBucket: ReasonBucket;
  ruleFired: RuleId;
  decision: Decision;
  actor: Actor;
  outcome: string;
  state: AgentState;
  attempt?: number;
  amount?: number; // in flow currency minor unit (paise for INR)
  currency?: string;
  invoiceId?: string;
  customerId?: string;
  channel?: string; // email | sms | whatsapp | voice | api
  notes?: string;
  // Tamper-evidence hash chain (added additively; do not alter existing fields).
  prevHash?: string; // hash of the immediately preceding log entry (GENESIS_HASH for first)
  hash?: string; // sha256(prevHash + stable_stringify(entry minus hash fields))
}

// A normalized event that any flow can consume. Producers (Razorpay webhooks,
// checkout analytics, ERP receivable extracts) normalize into this shape.
export interface FlowEvent {
  eventId: string;
  flow: FlowType;
  customerId: string;
  customerName: string;
  customerPhone?: string;
  customerEmail?: string;
  amount: number; // minor unit
  currency: string;
  occurredAt: number; // epoch ms
  // flow-specific details
  subscriptionId?: string;
  invoiceId?: string;
  orderId?: string;
  planId?: string;
  // raw signal for diagnosis (error codes, PTP date, overdue days, etc.)
  signal?: Record<string, unknown>;
}

export interface TouchResult {
  success: boolean;
  channel: string;
  detail?: string;
  stoppedByDnc?: boolean; // do-not-call / TPS / opt-out
  incentiveApplied?: boolean;
}

export interface RecoveryContext {
  eventId: string;
  flow: FlowType;
  customerId: string;
  invoiceId: string;
  amount: number;
  currency: string;
  reason: ReasonBucket;
  attempt: number; // 0-based recovery attempts so far
  touchesForCustomer: number; // total outbound touches for this customer
  activePromiseToPayDate?: number | null; // epoch ms
  overdueDays?: number;
  now?: number;
  // flow-specific
  retryWindow?: { start: number; end: number }; // mandate retry windows
  ptpSupervisor?: boolean; // PTP needs human supervisor sign-off
  dncFlag?: boolean; // telecom DNC / TPS / opt-out flag
  cartValue?: number; // abandoned cart value (minor unit)
  visits?: number; // visitor count for checkout spam guard
  rollingSuccessRate?: number; // payment success rate rollup
}

export type EvaluatedStep = {
  state: AgentState;
  ruleFired: RuleId;
  decision: Decision;
  outcome: string;
  retryAt?: number;
  channel?: string;
  incentive?: string;
  hold?: boolean;
};
