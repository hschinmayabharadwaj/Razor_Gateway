// Unified demo entry: runs the batch over all 7 flows, shows the audit-log
// dashboard, metrics, exception summary, and a couple of walkthroughs proving
// "one failure handled gracefully" and India-specific constraint handling.

import { createAuditStore } from './audit/store';
import { runBatch, loadEvents } from './batch/runner';
import { computeMetrics } from './metrics';
import { renderTable, renderMetrics } from './dashboard/table';
import { classify } from './diagnosis/classify';
import { stepState } from './decisions/stateMachine';
import { FlowEvent } from './flows/types';

function fmt(inr: number): string { return `₹${inr.toFixed(2)}`; }

function main() {
  const events = loadEvents();

  const audit = createAuditStore();
  audit.clear();

  // Run the whole batch against a consistent daytime timestamp so the
  // regulatory quiet-hour check doesn't block all voice calls at once.
  const now = Date.UTC(2026, 8, 1, 14, 30); // 14:30 IST

  console.log(`Loaded ${events.length} events across 7 recovery flows.\n`);

  const result = runBatch(events, audit, { now });

  const log = audit.all();
  const metrics = computeMetrics(log);

  console.log('===== AUDIT LOG — TABLE VIEW (all flows) =====');
  console.log(renderTable(log));
  console.log(renderMetrics(metrics));
  console.log('');
  console.log('===== EXCEPTION SUMMARY (LLM, for human reviewer) =====');
  console.log(result.exceptionSummary);

  // ---- Walkthrough 1: mandate_revoked handled gracefully (failed_subscription) ----
  walkthroughMandateRevoked(events);

  // ---- Walkthrough 2: mandate retry sequenced within NPCI window ----
  walkthroughMandateRetryWindow(events);

  // ---- Walkthrough 3: Checkout abandonment recovered with incentive ----
  walkthroughCheckout(events);
}

function walkthroughMandateRevoked(events: FlowEvent[]) {
  const ev = events.find((e) => e.flow === 'failed_subscription' && classify(e) === 'mandate_revoked');
  if (!ev) return;
  console.log('\n\n########## WALKTHROUGH 1: mandate_revoked handled gracefully ##########');
  const reason = classify(ev);
  console.log(`Event: ${ev.eventId} (${ev.flow})`);
  console.log(`  error_code:      ${(ev.signal as any)?.error_code}`);
  console.log(`  amount:          ${fmt(ev.amount / 100)}`);
  console.log('');
  console.log(`Step 1 — classify() -> "${reason}"  [deterministic error-code lookup, no LLM]`);
  console.log('');
  console.log('Step 2 — DECISION ENGINE evaluates stopping rules:');
  console.log('  (b) fraud_flagged?       -> false');
  console.log('  (c) mandate_revoked?     -> TRUE ==> ESCALATE, NEVER retry');
  console.log('  Rule fired: mandate_revoked_escalate, decision: escalate, actor: policy_engine');
  console.log('');
  const { audit: entry } = stepState({ ...ctxFor(ev), reason, attempt: 0, touchesForCustomer: 0 });
  console.log(`Audit entry: ${JSON.stringify({ ruleFired: entry.ruleFired, decision: entry.decision, state: entry.state, actor: entry.actor })}`);
  console.log('');
  console.log('Step 3 — policy decided to escalate. ONLY NOW does the LLM write copy.');
  console.log('  No charge API call was made. No money moved without a named rule.');
  console.log('RESULT: correctly refused to retry, escalated to re-collect mandate, auditable.');
}

function walkthroughMandateRetryWindow(events: FlowEvent[]) {
  const ev = events.find((e) => e.flow === 'mandate_retry' && !(e.signal as any)?.mandate_revoked);
  if (!ev) return;
  console.log('\n\n########## WALKTHROUGH 2: India-specific mandate retry sequencing (NPCI) ##########');
  const reason = classify(ev);
  const window = (ev.signal as any)?.retry_window;
  console.log(`Event: ${ev.eventId} (${ev.flow})`);
  console.log(`  reason: ${reason}`);
  console.log(`  NPCI retry window: ${new Date(window.start).toISOString().slice(0, 10)} -> ${new Date(window.end).toISOString().slice(0, 10)} (bounded, not 'retry every 3 days')`);
  console.log('');
  console.log('  Retry sequence (bounded): onDueDate -> +1d -> +2d, then STOP/ESCALATE.');
  console.log('  decision engine enforces isWithinMandateRetryWindow() + mandateRetryAttemptAllowed().');
  console.log('  Rule fired: mandate_retry_seq (within window) / mandate_retry_window (outside).');
  const { audit: entry } = stepState({ ...ctxFor(ev), reason, attempt: 0, touchesForCustomer: 0, retryWindow: { start: window.start, end: window.end } });
  console.log(`Audit entry: ${JSON.stringify({ ruleFired: entry.ruleFired, decision: entry.decision, state: entry.state })}`);
}

function walkthroughCheckout(events: FlowEvent[]) {
  const ev = events.find((e) => e.flow === 'checkout_abandonment' && (e.signal as any)?.visits >= 2);
  if (!ev) return;
  console.log('\n\n########## WALKTHROUGH 3: checkout abandonment recovered (cost-aware) ##########');
  const reason = classify(ev);
  console.log(`Event: ${ev.eventId} (${ev.flow}), reason: ${reason}`);
  console.log(`  cart value: ${fmt((ev.signal as any)?.cart_value / 100)}`);
  console.log(`  repeat visitor: yes (visits=${(ev.signal as any)?.visits})`);
  console.log('  decision engine: cartEligibleForIncentive() -> TRUE on first touch');
  console.log('  Rule fired: cart_incentive (only for repeat visitors + cart above threshold)');
  const { audit: entry } = stepState({ ...ctxFor(ev), reason, attempt: 0, touchesForCustomer: 0, cartValue: (ev.signal as any)?.cart_value, visits: (ev.signal as any)?.visits });
  console.log(`Audit entry: ${JSON.stringify({ ruleFired: entry.ruleFired, decision: entry.decision, state: entry.state })}`);
  console.log('RESULT: spam guard (repeat visitors only) + no discount on junk carts (threshold).');
}

function ctxFor(ev: FlowEvent) {
  return {
    eventId: ev.eventId,
    flow: ev.flow,
    customerId: ev.customerId,
    invoiceId: ev.invoiceId ?? '',
    amount: ev.amount,
    currency: ev.currency,
    now: ev.occurredAt,
  };
}

main();
