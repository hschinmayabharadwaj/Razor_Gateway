// Unified pure state transition for any flow. Given a RecoveryContext, the
// engine picks the next state + audit entry. No side effects; decision made by
// the deterministic per-flow engine with a named rule.

import { AuditEntry, AgentState, FlowType, RecoveryContext, RuleId, Decision, EvaluatedStep, Actor } from '../flows/types';
import { decideForFlow } from './engines';

export interface StepResult {
  next: EvaluatedStep;
  audit: AuditEntry;
}

export function stepState(ctx: RecoveryContext): StepResult {
  if (!ctx) throw new Error('stepState: missing context');

  const input = {
    reason: ctx.reason,
    currentAttempt: ctx.attempt,
    touchesForCustomer: ctx.touchesForCustomer,
    activePromiseToPayDate: ctx.activePromiseToPayDate ?? null,
    overdueDays: ctx.overdueDays,
    now: ctx.now,
    retryWindow: ctx.retryWindow,
    dncFlag: ctx.dncFlag,
    cartValue: ctx.cartValue,
    visits: ctx.visits,
    rollingSuccessRate: ctx.rollingSuccessRate,
  };

  const d = decideForFlow(ctx.flow, input);
  const ts = new Date(ctx.now ?? Date.now()).toISOString();

  const base = {
    eventId: ctx.eventId,
    timestamp: ts,
    flow: ctx.flow,
    reasonBucket: ctx.reason,
    customerId: ctx.customerId,
    invoiceId: ctx.invoiceId,
    amount: ctx.amount,
    currency: ctx.currency,
    attempt: ctx.attempt,
  };

  const rule = d.ruleFired as RuleId;
  const decision = d.decision as Decision;

  const next: EvaluatedStep = {
    state: stateFor(decision, ctx.flow),
    ruleFired: rule,
    decision,
    outcome: outcomeFor(ctx, rule, decision),
  };

  const actor: Actor = 'policy_engine';
  const audit: AuditEntry = { ...base, ruleFired: rule, decision, actor, state: next.state, outcome: next.outcome };

  return { next, audit };
}

function stateFor(decision: Decision, flow: FlowType): AgentState {
  switch (decision) {
    case 'recover': return 'recovered';
    case 'escalate': return 'escalated';
    case 'suppress': return 'suppressed';
    case 'abandon': return 'abandoned';
    case 'hold': return flow === 'promise_to_pay' ? 'waiting_on_ptp' : 'retry_scheduled';
    case 'contact': return 'contact_scheduled';
    case 'retry': return 'retry_scheduled';
    default: return 'detected';
  }
}

function outcomeFor(ctx: RecoveryContext, rule: RuleId, decision: Decision): string {
  const who = ctx.customerId;
  switch (rule) {
    case 'fraud_suppress': return `Suppressed all recovery for ${who} (fraud/risk)`;
    case 'mandate_revoked_escalate': return `Escalated ${ctx.eventId} to human (mandate revoked, never retried)`;
    case 'promise_to_pay_suppress':
    case 'ptp_suppress': return `Suppressed touches for ${who} until active promise-to-pay date passes`;
    case 'exhaust_attempts_escalate': return `Escalated ${ctx.eventId} to human after ${ctx.attempt} failed retries`;
    case 'max_touches_cap': return `Stopped recovery for ${who}: outbound touch cap reached`;
    case 'mandate_retry_window': return `Held ${ctx.eventId}: outside NPCI mandate retry window`;
    case 'mandate_retry_seq': return `Sequenced ${ctx.eventId} retry within mandate window`;
    case 'transient_retry': return `Scheduled retry attempt ${ctx.attempt + 1} for ${ctx.eventId}`;
    case 'checkout_reminder': return `Sending checkout reminder for abandoned cart ${ctx.eventId}`;
    case 'cart_incentive': return `Offering cart incentive to recover abandoned checkout ${ctx.eventId}`;
    case 'checkout_abandon': return `Abandoned checkout recovery for ${ctx.eventId} (error/edge)`;
    case 'repeat_visitor_only': return `Abandoned ${ctx.eventId}: one-time visitor, no recovery (spam guard)`;
    case 'invoice_reminder': return `Sent dunning reminder for receivable ${ctx.eventId}`;
    case 'invoice_escalate_dunning': return `Escalated receivable ${ctx.eventId} to collections (dunning)`;
    case 'dispute_hold': return `Held receivable ${ctx.eventId}: disputed, routed to collections`;
    case 'degradation_alert': return `Alerted on payment degradation for ${ctx.eventId}`;
    case 'degradation_recover': return `Recovered from degradation window for ${ctx.eventId}`;
    case 'degradation_escalate': return `Escalated degradation (issuer down) for ${ctx.eventId}`;
    case 'voice_call': return `Placing Hinglish voice recovery call for ${ctx.eventId}`;
    case 'voice_retry': return `Retrying voice call for ${ctx.eventId} (unreachable)`;
    case 'voice_do_not_call': return `Stopped voice recovery for ${who}: DNC / quiet hours`;
    case 'voice_escalate_human': return `Escalated voice recovery for ${ctx.eventId} to human agent`;
    case 'ptp_schedule': return `Scheduled promise-to-pay follow-up for ${ctx.eventId}`;
    case 'ptp_reminder_before': return `Sent PTP reminder before due date for ${ctx.eventId}`;
    case 'ptp_followup': return `Following up after promise-to-pay date for ${ctx.eventId}`;
    case 'ptp_missed_escalate': return `Escalated promise-to-pay (missed/broken) for ${ctx.eventId}`;
    default: return `${decision} via ${rule} for ${ctx.eventId}`;
  }
}
