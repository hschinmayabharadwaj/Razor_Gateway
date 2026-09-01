// Deterministic classification per flow. Each flow maps its raw signal/error
// code onto ONE narrow reason bucket. Pure functions, no LLM.

import { FlowEvent, FlowType, ReasonBucket } from '../flows/types';

// Enum of our finite reason buckets per flow (narrow taxonomy)
export const PAYMENT_BUCKETS: readonly ReasonBucket[] = [
  'insufficient_funds',
  'card_expired',
  'mandate_revoked',
  'bank_declined_transient',
  'auth_3ds_abandoned',
  'fraud_flagged',
];

// ---------------------------------------------------------------------------
// Razorpay error-code map (shared by subscription + mandate + payment flows)
// ---------------------------------------------------------------------------
const RAZORPAY_ERROR_CODES: Record<string, ReasonBucket> = {
  BAD_REQUEST_ERROR: 'insufficient_funds',
  CARD_DECLINED: 'insufficient_funds',
  CARD_EXPIRED: 'card_expired',
  CARD_EXPIRED_CODE: 'card_expired',
  DIRECTORAUTHPARAM_FAILED: 'auth_3ds_abandoned',
  ISSUER_UNAVAILABLE: 'bank_declined_transient',
  UNAUTHORIZED_PAYMENT: 'bank_declined_transient',
  PAYMENT_AUTHENTICATION_FAILED: 'bank_declined_transient',
  BANK_REFUND_DECLINED: 'bank_declined_transient',
  NETWORK_ERROR: 'bank_declined_transient',
  MANDATE_REVOKED: 'mandate_revoked',
  MANDATE_INVALID: 'mandate_revoked',
  MANDATE_CANCELLED: 'mandate_revoked',
  FRAUD_DETECTED: 'fraud_flagged',
  RISK_DECLINE: 'fraud_flagged',
  AUTH_FAILED: 'auth_3ds_abandoned',
  CUSTOMER_ABANDONED: 'auth_3ds_abandoned',
  AUTH_ACCEPTED_LATER: 'auth_3ds_abandoned',
  SUCCESS_RATE_DROP: 'success_rate_drop',
  LATENCY_SPIKE: 'latency_spike',
  ISSUER_DOWN: 'issuer_down',
};

interface Signal {
  [k: string]: unknown;
}

function pickBucketFromCode(code: string | undefined): ReasonBucket | undefined {
  if (!code) return undefined;
  return RAZORPAY_ERROR_CODES[code.toUpperCase()];
}

// ---------------------------------------------------------------------------
// Flow 3: failed subscription / mandate retry
// ---------------------------------------------------------------------------
export function classifySubscription(signal: Signal): ReasonBucket {
  const code = pickBucketFromCode(signal.error_code as string);
  if (code) return code;
  const desc = `${signal.error_description ?? ''} ${signal.error_reason ?? ''}`.toLowerCase();
  if (desc.includes('insufficient') || desc.includes('limit')) return 'insufficient_funds';
  if (desc.includes('expired')) return 'card_expired';
  if (desc.includes('mandate') && (desc.includes('revoke') || desc.includes('cancel') || desc.includes('invalid')))
    return 'mandate_revoked';
  if (desc.includes('fraud') || desc.includes('risk') || desc.includes('suspicious')) return 'fraud_flagged';
  if (desc.includes('abandoned') || desc.includes('3ds') || desc.includes('auth')) return 'auth_3ds_abandoned';
  return 'bank_declined_transient';
}

// ---------------------------------------------------------------------------
// Flow 2: checkout abandonment
// ---------------------------------------------------------------------------
export function classifyCheckout(signal: Signal): ReasonBucket {
  const step = (signal.abandoned_at_step as string) ?? '';
  const err = (signal.error as string) ?? '';
  if (err && err.length > 0) return 'checkout_error';
  if (step.includes('payment') || step.includes('otp') || step.includes('upi')) return 'payment_step_abandoned';
  if (step.includes('address')) return 'address_abandoned';
  if ((signal.page_load_ms as number) > 5000) return 'slow_checkout';
  if (signal.price_mismatch === true) return 'price_mismatch';
  return 'payment_step_abandoned';
}

// ---------------------------------------------------------------------------
// Flow 4: B2B receivables
// ---------------------------------------------------------------------------
export function classifyReceivable(signal: Signal): ReasonBucket {
  const disputed = signal.disputed === true || (signal.dispute_note && (signal.dispute_note as string).length > 0);
  if (disputed) return 'disputed_receivable';
  const overdueDays = (signal.overdue_days as number) ?? 0;
  if (overdueDays < 60) return 'overdue_net30';
  return 'overdue_net60';
}

// ---------------------------------------------------------------------------
// Flow 1: payment degradation
// ---------------------------------------------------------------------------
export function classifyDegradation(signal: Signal): ReasonBucket {
  const code = pickBucketFromCode(signal.error_code as string);
  if (code) return code;
  if ((signal.success_rate as number) < 0.85) return 'success_rate_drop';
  if ((signal.latency_ms as number) > 2000) return 'latency_spike';
  if (signal.issuer_down === true) return 'issuer_down';
  return 'bank_declined_transient';
}

// ---------------------------------------------------------------------------
// Flow 6: Hinglish voice
// ---------------------------------------------------------------------------
export function classifyVoice(signal: Signal): ReasonBucket {
  const state = (signal.call_state as string) ?? '';
  if (state === 'missed' || state === 'no_answer') return 'voice_missed_call';
  if (state === 'call_back_requested') return 'voice_asked_call_back';
  return 'voice_unreachable';
}

// ---------------------------------------------------------------------------
// Flow 7: Promise-to-pay tracker
// ---------------------------------------------------------------------------
export function classifyPromiseToPay(signal: Signal): ReasonBucket {
  const status = (signal.ptp_status as string) ?? '';
  if (status === 'broken') return 'ptp_broken';
  if (status === 'missed') return 'ptp_missed';
  if (status === 'committed') return 'ptp_committed';
  return 'ptp_committed';
}

// Dispatch: normalize any FlowEvent's signal into one reason bucket.
export function classify(event: FlowEvent): ReasonBucket {
  const signal = event.signal ?? {};
  switch (event.flow) {
    case 'failed_subscription':
    case 'mandate_retry':
      return classifySubscription(signal);
    case 'checkout_abandonment':
      return classifyCheckout(signal);
    case 'b2b_receivables':
      return classifyReceivable(signal);
    case 'payment_degradation':
      return classifyDegradation(signal);
    case 'hinglish_voice':
      return classifyVoice(signal);
    case 'promise_to_pay':
      return classifyPromiseToPay(signal);
  }
}
