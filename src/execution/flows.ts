// Execution layer: for each flow, execute the bounded recovery action decided
// by the policy engine. Returns touch/recovery results. No decision is made
// here — this only runs what the engine already decided.

import { FlowEvent, FlowType, ReasonBucket, TouchResult, RecoveryContext } from '../flows/types';

// Execution mode controls whether a money-moving "charge" interaction is
// simulated or could reach a live provider. SAFETY INVARIANT: the sandbox /
// backtest path MUST always run in 'sandbox' mode, where charge execution is a
// pure, in-process simulation that can never call a real Razorpay charge API.
// 'live' is reserved for production and requires an explicit authenticated
// call site (see security/).
export type ExecutionMode = 'sandbox' | 'live';

export const SANDBOX_GUARANTEE =
  'Sandbox/backtest mode never calls a live or test-mode charge API — ' +
  'charge interactions in sandbox are pure in-process simulations.';

// Deterministic seeded PRNG so the demo/replays are stable per event+attempt.
function seededRandom(seedStr: string, salt = 0): number {
  let seed = 0;
  for (const ch of seedStr) seed += ch.charCodeAt(0);
  seed += salt * 9973;
  const r = ((seed * 2654435761) >>> 0) / 4294967296;
  return r;
}

export interface ExecutionResult {
  success: boolean;
  channel: string;
  detail?: string;
  recovered?: boolean;
  recoveredAmount?: number;
  dncBlocked?: boolean;
  note?: string;
}

// Simulated "attempt a recovery touch" per flow/channel. Deterministic.
export function executeAction(
  event: FlowEvent,
  flow: FlowType,
  reason: ReasonBucket,
  attempt: number,
  mode: ExecutionMode = 'sandbox',
): ExecutionResult {
  // Structural isolation: a sandbox run can NEVER perform a live charge. The
  // charge-capable branches immediately short-circuit to a pure simulation and
  // no provider call is reachable from this code path.
  if (mode === 'sandbox') {
    // charge-capable flows still resolve deterministically, never via network
    switch (flow) {
      case 'failed_subscription':
      case 'mandate_retry':
        return executeRetryCharge(event, reason, attempt);
      case 'checkout_abandonment':
        return executeCheckoutTouch(event, reason, attempt);
      case 'b2b_receivables':
        return executeReceivableTouch(event, reason, attempt);
      case 'payment_degradation':
        return executeDegradation(tryDec(event));
      case 'hinglish_voice':
        return executeVoiceCall(event, reason, attempt);
      case 'promise_to_pay':
        return executePtpFollowUp(event, reason, attempt);
    }
  }
  // Live mode: would delegate to a real, authenticated provider adapter. That
  // adapter is intentionally not wired in this repo; the seam exists so the
  // isolation boundary is explicit rather than implicit.
  switch (flow) {
    case 'failed_subscription':
    case 'mandate_retry':
      return executeRetryCharge(event, reason, attempt);
    case 'checkout_abandonment':
      return executeCheckoutTouch(event, reason, attempt);
    case 'b2b_receivables':
      return executeReceivableTouch(event, reason, attempt);
    case 'payment_degradation':
      return executeDegradation(tryDec(event));
    case 'hinglish_voice':
      return executeVoiceCall(event, reason, attempt);
    case 'promise_to_pay':
      return executePtpFollowUp(event, reason, attempt);
  }
  throw new Error(`unhandled flow ${flow}`);
}

function executeRetryCharge(event: FlowEvent, reason: ReasonBucket, attempt: number): ExecutionResult {
  const id = event.eventId;
  const r = seededRandom(id, attempt);
  let prob = 0;
  switch (reason) {
    case 'bank_declined_transient': prob = 0.7; break;
    case 'mandate_insufficient':
    case 'insufficient_funds': prob = 0.5; break;
    case 'card_expired': prob = 0.35; break;
    case 'mandate_bank_down': prob = 0.6; break;
    case 'mandate_auth_pending':
    case 'auth_3ds_abandoned': prob = 0.3; break;
    default: prob = 0; // never retried
  }
  const success = r < prob;
  const payId = `pay_retry_${id}_${attempt}`;
  return {
    success,
    channel: 'api',
    recovered: success,
    recoveredAmount: success ? event.amount : 0,
    detail: success
      ? `Retry attempt ${attempt + 1} succeeded (${payId})`
      : `Retry attempt ${attempt + 1} failed (${reason})`,
  };
}

function executeCheckoutTouch(event: FlowEvent, _reason: ReasonBucket, attempt: number): ExecutionResult {
  // channel progression: email -> whatsapp (reminders), with incentive on touch 1
  const channel = attempt === 0 ? 'email' : 'whatsapp';
  const r = seededRandom(event.eventId, attempt);
  const success = r < 0.4; // ~40% of abandoned carts recovered via reminder
  return {
    success,
    channel,
    recovered: success,
    recoveredAmount: success ? event.amount : 0,
    detail: success
      ? `Recovered abandoned cart ${event.eventId} via ${channel}${attempt === 0 ? ' (incentive applied)' : ''}`
      : `Checkout reminder sent (${channel}), no recovery yet`,
  };
}

function executeReceivableTouch(event: FlowEvent, _reason: ReasonBucket, attempt: number): ExecutionResult {
  const channel = attempt === 0 ? 'email' : attempt === 1 ? 'whatsapp' : 'sms';
  const r = seededRandom(event.eventId, attempt);
  const success = r < 0.35;
  return {
    success,
    channel,
    recovered: success,
    recoveredAmount: success ? event.amount : 0,
    detail: success
      ? `B2B receivable ${event.eventId} collected via ${channel}`
      : `Dunning touch sent for ${event.eventId} (${channel})`,
  };
}

function executeDegradation(recover: boolean | undefined): ExecutionResult {
  return {
    success: true,
    channel: 'api',
    recovered: recover === true,
    recoveredAmount: 0,
    detail: recover === true
      ? 'Degradation window cleared; success rate back above threshold'
      : 'Degradation detected; alert triggered',
  };
}

function executeVoiceCall(event: FlowEvent, _reason: ReasonBucket, attempt: number): ExecutionResult {
  // TRAI regulatory: voice recovery with metrics (answered, asked-callback)
  const r = seededRandom(event.eventId, attempt);
  const answered = r < 0.5;
  if (!answered) {
    return { success: false, channel: 'voice', detail: 'Missed call / no answer', note: 'retry once more' };
  }
  const recovered = r < 0.3;
  return {
    success: true,
    channel: 'voice',
    recovered,
    recoveredAmount: recovered ? event.amount : 0,
    detail: recovered
      ? `Hinglish voice call converted (customer paid)`
      : `Hinglish voice call answered; customer requested callback`,
  };
}

function executePtpFollowUp(event: FlowEvent, _reason: ReasonBucket, attempt: number): ExecutionResult {
  const r = seededRandom(event.eventId, attempt);
  const recovered = r < 0.5;
  return {
    success: true,
    channel: 'email',
    recovered,
    recoveredAmount: recovered ? event.amount : 0,
    detail: recovered
      ? `Promise-to-pay honored after follow-up`
      : `Promise-to-pay reminder sent, awaiting payment`,
  };
}

function tryDec(event: FlowEvent): boolean | undefined {
  // payment_degradation: recovered if event carries a success signal
  const s = event.signal;
  return (s?.recovered as boolean | undefined) ?? undefined;
}

export type { TouchResult };
