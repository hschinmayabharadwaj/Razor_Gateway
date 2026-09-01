// Unified batch orchestrator. Drives every FlowEvent through the decision
// engine / state machine, executes the decided action, generates LLM copy only
// after a decision, and appends every transition to the audit log.
// The engine decides; this loop only executes and logs.

import { FlowEvent, FlowType, AgentState, AuditEntry, RecoveryContext } from '../flows/types';
import { classify } from '../diagnosis/classify';
import { stepState } from '../decisions/stateMachine';
import { executeAction } from '../execution/flows';
import { generateCopy, generateExceptionSummary } from '../execution/copy';
import { AuditStore } from '../audit/store';
import { MAX_BATCH_ATTEMPTS } from '../decisions/rules';

export interface BatchResult {
  auditEntries: AuditEntry[];
  escapes: { eventId: string; subject: string; flow: FlowType }[];
  exceptionSummary: string;
  batchAttemptLimitHit: boolean;
}

export interface RunnerOpts {
  now?: number;
  maxBatchAttempts?: number;
}

// Subset of RecoveryContext built once per event (fields constant across attempts).
type RecoveryContextBase = Pick<
  RecoveryContext,
  'eventId' | 'flow' | 'customerId' | 'invoiceId' | 'amount' | 'currency' | 'reason' | 'now'
>;

export function runBatch(events: FlowEvent[], audit: AuditStore, opts?: RunnerOpts): BatchResult {
  let batchAttemptLimitHit = false;
  const maxBatch = opts?.maxBatchAttempts ?? MAX_BATCH_ATTEMPTS();
  let used = 0;

  // Per-customer touch tracking across events (blast radius, not per-event).
  const touchesByCustomer = new Map<string, number>();

  const escapes: BatchResult['escapes'] = [];
  const escalatedEvents: AuditEntry[] = [];

  for (const event of events) {
    if (used >= maxBatch) { batchAttemptLimitHit = true; break; }

    const reason = classify(event);
    const now = opts?.now ?? Date.now();

    const ctxBase: RecoveryContextBase = {
      eventId: event.eventId,
      flow: event.flow,
      customerId: event.customerId,
      invoiceId: event.invoiceId ?? '',
      amount: event.amount,
      currency: event.currency,
      reason,
      now,
    };

    let attempt = 0;
    let state: AgentState = 'detected';
    let guard = 0;

    while (!isTerminal(state) && guard < 100) {
      guard++;
      if (used >= maxBatch) { batchAttemptLimitHit = true; break; }
      used++;

      const ctx = flowContext(event, ctxBase, attempt, touchesByCustomer);
      const { next, audit: entry } = stepState(ctx);
      audit.append(entry);
      state = next.state;

      switch (next.decision) {
        case 'retry':
        case 'contact': {
          const res = executeAction(event, event.flow, reason, attempt);
          touchesByCustomer.set(event.customerId, (touchesByCustomer.get(event.customerId) ?? 0) + 1);
          const actionEntry: AuditEntry = {
            ...entry,
            ruleFired: res.recovered ? 'recovered' : entry.ruleFired,
            decision: res.recovered ? 'recover' : entry.decision,
            state: res.recovered ? 'recovered' : entry.state === 'contact_scheduled' ? 'contacting' : 'retrying',
            channel: res.channel,
            outcome: res.detail ?? '',
            actor: 'policy_engine',
            attempt,
            notes: res.note,
          };
          audit.append(actionEntry);
          attempt++;
          if (res.recovered) {
            audit.append({ ...actionEntry, ruleFired: 'recovered', decision: 'recover', state: 'recovered', outcome: `Recovered ${(res.recoveredAmount ?? 0) / 100} ${event.currency}` });
            state = 'recovered';
          }
          break;
        }
        case 'escalate': {
          // LLM copy ONLY after policy decided to escalate.
          const copy = generateCopy({
            eventId: event.eventId,
            flow: event.flow,
            customerName: event.customerName,
            customerEmail: event.customerEmail,
            amountInRupees: event.amount / 100,
            reason,
            invoiceId: event.invoiceId,
            overdueDays: (event.signal?.overdue_days as number) ?? undefined,
          });
          audit.append({
            ...entry,
            ruleFired: 'no_op',
            decision: 'escalate',
            actor: 'llm_copy',
            state: 'escalated',
            outcome: `Generated ${copy.channel} message: ${copy.subject}`,
          });
          escapes.push({ eventId: event.eventId, subject: copy.subject, flow: event.flow });
          if (!escalatedEvents.some((e) => e.eventId === event.eventId)) escalatedEvents.push(entry);
          state = 'escalated';
          break;
        }
        case 'hold': {
          // Park the event for a later scheduled run (mandate window, dispute,
          // PTP-wait). Not terminal, but we must NOT re-evaluate in this loop
          // (otherwise it would spin forever). A later scheduled run re-evaluates.
          audit.append({
            ...entry,
            ruleFired: entry.ruleFired,
            decision: 'hold',
            actor: 'policy_engine',
            state: 'waiting_on_ptp',
            outcome: `Held ${event.eventId} (${entry.ruleFired}) pending next scheduled window`,
          });
          state = 'waiting_on_ptp';
          break;
        }
        case 'none': {
          // No action warranted (e.g. receivable under dunning threshold).
          // Park it as a terminal no-op for this run; a later run re-evaluates.
          audit.append({
            ...entry,
            ruleFired: entry.ruleFired,
            decision: 'none',
            actor: 'policy_engine',
            state: 'abandoned',
            outcome: `No recovery action warranted for ${event.eventId} (${entry.ruleFired})`,
          });
          state = 'abandoned';
          break;
        }
        case 'suppress':
        case 'abandon':
        case 'recover':
        default:
          // terminal-ish; loop guard will exit
          break;
      }
    }
  }

  const exceptionSummary = generateExceptionSummary(
    escalatedEvents.map((e) => ({
      eventId: e.eventId,
      flow: e.flow,
      reason: e.reasonBucket,
      amountInRupees: (e.amount ?? 0) / 100,
    })),
  ).text;

  return { auditEntries: audit.all(), escapes, exceptionSummary, batchAttemptLimitHit };
}

function flowContext(
  event: FlowEvent,
  base: RecoveryContextBase,
  attempt: number,
  touchesByCustomer: Map<string, number>,
) {
  const s = event.signal ?? {};
  return {
    ...base,
    attempt,
    touchesForCustomer: touchesByCustomer.get(event.customerId) ?? 0,
    activePromiseToPayDate: (s.ptp_date as number) ?? null,
    overdueDays: (s.overdue_days as number) ?? 0,
    retryWindow: s.retry_window ? { start: (s.retry_window as any).start, end: (s.retry_window as any).end } : undefined,
    dncFlag: (s.dnc_flag as boolean) ?? false,
    cartValue: (s.cart_value as number) ?? 0,
    visits: (s.visits as number) ?? 1,
    rollingSuccessRate: (s.success_rate as number) ?? 1,
  };
}

function isTerminal(s: AgentState): boolean {
  return s === 'recovered' || s === 'escalated' || s === 'abandoned' || s === 'suppressed' || s === 'waiting_on_ptp';
}

import * as fs from 'fs';
import * as path from 'path';
export function loadEvents(dir = 'data/flows'): FlowEvent[] {
  const p = path.join(process.cwd(), dir);
  const files = fs.readdirSync(p).filter((f) => f.endsWith('.json'));
  return files.map((f) => JSON.parse(fs.readFileSync(path.join(p, f), 'utf8')) as FlowEvent);
}
