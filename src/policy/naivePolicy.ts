// NAIVE POLICY ENGINE — deliberately unsafe baseline.
// Has NO safety rules: retries every failure blindly up to 10 attempts on a
// fixed 3-day cadence, regardless of reason bucket (including fraud_flagged
// and mandate_revoked), with no touch cap, no DNC/quiet-hours check, and no
// PTP suppression. This represents "what most naive systems actually do."
//
// It reuses the same execution plumbing; only the decision function differs,
// and we track every proposed touch so the real rule predicates can later re-
// check it (see compare.ts).

import { FlowEvent, AgentState, AuditEntry } from '../flows/types';
import { classify } from '../diagnosis/classify';
import { executeAction } from '../execution/flows';
import { AuditStore } from '../audit/store';

export const NAIVE_MAX_ATTEMPTS = 10; // blind, up to 10 attempts
export const NAIVE_CADENCE_DAYS = 3; // retry every 3 days

// Every touch the naive policy proposes, captured so real rules can re-check it.
export interface NaiveTouch {
  eventId: string;
  flow: FlowEvent['flow'];
  customerId: string;
  reason: ReturnType<typeof classify>;
  attempt: number; // 0-based within this event
  touchesForCustomer: number; // touches so far for this customer at decision time
  channel: string;
  now: number; // decision timestamp (for quiet-hours check)
  dncFlag: boolean;
  activePromiseToPayDate: number | null;
}

export interface NaiveRun {
  auditEntries: AuditEntry[];
  touches: NaiveTouch[];
}

// Blind decision: always act (retry/contact), regardless of reason, up to 10.
export function naiveShouldAct(attempt: number): boolean {
  return attempt < NAIVE_MAX_ATTEMPTS;
}

export function runNaiveBatch(events: FlowEvent[], audit: AuditStore, opts?: { now?: number }): NaiveRun {
  const nowBase = opts?.now ?? Date.now();
  const touches: NaiveTouch[] = [];

  for (const event of events) {
    const reason = classify(event);
    const s = event.signal ?? {};
    const dncFlag = (s.dnc_flag as boolean) ?? false;
    const activePromiseToPayDate = (s.ptp_date as number) ?? null;

    let attempt = 0;
    let state: AgentState = 'detected';

    let touchCount = 0;
    while (naiveShouldAct(attempt) && state !== 'recovered') {
      const touchAt = nowBase + attempt * NAIVE_CADENCE_DAYS * 86400000; // simulated 3-day cadence
      const touchesForCustomer = touches.filter((t) => t.customerId === event.customerId).length;

      touchCount++;
      touches.push({
        eventId: event.eventId,
        flow: event.flow,
        customerId: event.customerId,
        reason,
        attempt,
        touchesForCustomer,
        channel: event.flow === 'hinglish_voice' ? 'voice' : 'api',
        now: touchAt,
        dncFlag,
        activePromiseToPayDate,
      });

      const res = executeAction(event, event.flow, reason, attempt);
      const actionEntry: AuditEntry = {
        eventId: event.eventId,
        timestamp: new Date(touchAt).toISOString(),
        flow: event.flow,
        reasonBucket: reason,
        ruleFired: 'schedule_retry',
        decision: res.recovered ? 'recover' : 'retry',
        actor: 'policy_engine',
        outcome: res.detail ?? `Blind retry attempt ${attempt + 1}`,
        state: res.recovered ? 'recovered' : 'retrying',
        attempt,
        amount: event.amount,
        currency: event.currency,
        invoiceId: event.invoiceId,
        customerId: event.customerId,
        channel: res.channel,
        notes: 'naive_policy',
      };
      audit.append(actionEntry);
      attempt++;

      if (res.recovered) {
        audit.append({
          ...actionEntry,
          ruleFired: 'recovered',
          decision: 'recover',
          state: 'recovered',
          outcome: `Recovered ${(res.recoveredAmount ?? 0) / 100} ${event.currency}`,
          notes: 'naive_policy',
        });
        state = 'recovered';
      }
    }

    // Naive policy never suppresses/escalates on mandate/fraud: it just spends
    // the whole blind budget. Park as abandoned (budget exhausted, no recovery).
    if (state !== 'recovered') {
      audit.append({
        eventId: event.eventId,
        timestamp: new Date(nowBase).toISOString(),
        flow: event.flow,
        reasonBucket: reason,
        ruleFired: 'no_op',
        decision: 'abandon',
        actor: 'policy_engine',
        outcome: `Naive policy exhausted ${attempt}/${NAIVE_MAX_ATTEMPTS} blind attempts without recovery`,
        state: 'abandoned',
        attempt,
        amount: event.amount,
        currency: event.currency,
        invoiceId: event.invoiceId,
        customerId: event.customerId,
        notes: 'naive_policy',
      });
    }
  }

  return { auditEntries: audit.all(), touches };
}
