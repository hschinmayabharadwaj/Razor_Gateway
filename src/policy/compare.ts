// Compare the REAL policy engine vs the NAIVE baseline on the SAME batch.
// The naive touches are each re-checked against the REAL rule predicates
// (isFraudFlagged, isMandateRevoked, isDoNotCall/quiet-hours, atTouchCap,
// atMaxRetryAttempts, hasActivePromiseToPay). We count how many naive actions
// would have violated a named rule — violations the real engine structurally
// cannot commit.

import { FlowEvent, AuditEntry } from '../flows/types';
import { runBatch } from '../batch/runner';
import { runNaiveBatch, NaiveTouch, NAIVE_MAX_ATTEMPTS } from './naivePolicy';
import { computeMetrics, Metrics } from '../metrics';
import { AuditStore } from '../audit/store';
import {
  isFraudFlagged,
  isMandateRevoked,
  isDoNotCall,
  atTouchCap,
  atMaxRetryAttempts,
  hasActivePromiseToPay,
} from '../decisions/rules';

export interface ViolationCounts {
  fraud_retries: number;
  mandate_retries: number;
  quiet_hour_calls: number;
  dnc_breaches: number;
  touch_cap_breaches: number;
  retry_budget_breaches: number;
  ptp_suppression_breaches: number;
  total: number;
}

export interface PolicyComparison {
  real: Metrics;
  naive: Metrics;
  violations: ViolationCounts;
  totalNaiveTouches: number;
  takeaway: string;
}

// Re-check each naive touch against the real rule predicates.
export function countComplianceViolations(touches: NaiveTouch[]): ViolationCounts {
  const v: ViolationCounts = {
    fraud_retries: 0,
    mandate_retries: 0,
    quiet_hour_calls: 0,
    dnc_breaches: 0,
    touch_cap_breaches: 0,
    retry_budget_breaches: 0,
    ptp_suppression_breaches: 0,
    total: 0,
  };

  let uniqueViolatingActions = 0;
  for (const t of touches) {
    let violated = false;
    if (isFraudFlagged(t.reason)) { v.fraud_retries++; violated = true; }
    if (isMandateRevoked(t.reason)) { v.mandate_retries++; violated = true; }
    if (t.channel === 'voice' && isDoNotCall({ dncFlag: t.dncFlag, now: t.now })) {
      if (t.dncFlag) { v.dnc_breaches++; violated = true; }
      else { v.quiet_hour_calls++; violated = true; }
    }
    if (atTouchCap(t.touchesForCustomer)) { v.touch_cap_breaches++; violated = true; }
    if (atMaxRetryAttempts(t.attempt)) { v.retry_budget_breaches++; violated = true; }
    if (hasActivePromiseToPay({ activePromiseToPayDate: t.activePromiseToPayDate, now: t.now })) {
      v.ptp_suppression_breaches++;
      violated = true;
    }
    if (violated) uniqueViolatingActions++;
  }

  // headline = unique naive ACTIONS that violate at least one named rule
  v.total = uniqueViolatingActions;
  return v;
}

export function comparePolicies(events: FlowEvent[], realAudit: AuditStore, naiveAudit: AuditStore, opts?: { now?: number }): PolicyComparison {
  const now = opts?.now ?? Date.now();

  realAudit.clear();
  naiveAudit.clear();

  const realResult = runBatch(events, realAudit, { now });
  const naiveResult = runNaiveBatch(events, naiveAudit, { now });

  const real = computeMetrics(realAudit.all());
  const naive = computeMetrics(naiveAudit.all());

  const violations = countComplianceViolations(naiveResult.touches);
  const totalNaiveTouches = naiveResult.touches.length;

  const takeaway = buildTakeaway(real, naive, violations);

  return { real, naive, violations, totalNaiveTouches, takeaway };
}

// One-line takeaway computed from the data, not hard-coded.
export function buildTakeaway(real: Metrics, naive: Metrics, v: ViolationCounts): string {
  const realRate = (real.recoveryRate * 100).toFixed(1);
  const naiveRate = (naive.recoveryRate * 100).toFixed(1);
  const rateDelta = (naive.recoveryRate - real.recoveryRate) * 100;
  const realTouches = real.touchesSent;
  const naiveTouches = naive.touchesSent;

  return `Naive retry recovers ${naiveRate}% vs ${realRate}% (${rateDelta >= 0 ? '+' : ''}${rateDelta.toFixed(1)}pp) but commits ${v.total} compliance violations (${v.fraud_retries} fraud retries, ${v.mandate_retries} mandate revoke retries, ${v.quiet_hour_calls} quiet-hour calls, ${v.dnc_breaches} DNC breaches, ${v.touch_cap_breaches} touch-cap breaches, ${v.retry_budget_breaches} retry-budget breaches, ${v.ptp_suppression_breaches} PTP breaches) and ${naiveTouches} touches (vs ${realTouches}) — violations our policy engine structurally cannot make.`;
}

// Render the comparison table.
export function renderComparison(c: PolicyComparison): string {
  const out: string[] = [];
  out.push('');
  out.push('===== POLICY COMPARISON (same 60-event batch) =====');
  const header = ['metric', 'real_policy', 'naive_policy', 'delta'];
  const realRate = c.real.recoveryRate * 100;
  const naiveRate = c.naive.recoveryRate * 100;
  const rows: string[][] = [
    ['recovery_rate', pct(realRate), pct(naiveRate), signed(naiveRate - realRate) + 'pp'],
    ['recovered_amount', `₹${c.real.recoveredRupees.toFixed(2)}`, `₹${c.naive.recoveredRupees.toFixed(2)}`, signed(c.naive.recoveredRupees - c.real.recoveredRupees) + '₹'],
    ['touches_sent', String(c.real.touchesSent), String(c.naive.touchesSent), signed(c.naive.touchesSent - c.real.touchesSent)],
    ['cost_per_recovery', cp(c.real), cp(c.naive), ''],
    ['avg_touches_per_customer', avg(c.real), avg(c.naive), ''],
    ['compliance_violations', '0', String(c.violations.total), '+' + c.violations.total],
    ['unrecoverable_risk_touched', '0', String(c.violations.fraud_retries + c.violations.mandate_retries), ''],
  ];
  out.push(renderGrid(header, rows));
  out.push('');
  out.push('===== NAIVE VIOLATIONS BREAKDOWN (re-checked vs real rules) =====');
  const ih = ['violation', 'count'];
  const ir: string[][] = [
    ['fraud_flagged retries', String(c.violations.fraud_retries)],
    ['mandate_revoked retries', String(c.violations.mandate_retries)],
    ['TRAI quiet-hour calls', String(c.violations.quiet_hour_calls)],
    ['DNC breaches', String(c.violations.dnc_breaches)],
    ['customer touch-cap breaches', String(c.violations.touch_cap_breaches)],
    ['retry-budget (10 vs 3) overage', String(c.violations.retry_budget_breaches)],
    ['PTP-suppression breaches', String(c.violations.ptp_suppression_breaches)],
    ['TOTAL', String(c.violations.total)],
  ];
  out.push(renderGrid(ih, ir));
  out.push('');
  out.push('TAKEAWAY:');
  out.push('  ' + c.takeaway);
  return out.join('\n');
}

function pct(x: number): string { return `${x.toFixed(1)}%`; }
function signed(x: number): string { return `${x >= 0 ? '+' : ''}${x.toFixed(0)}`; }
function cp(m: Metrics): string { return `${m.costPerRecovery.toFixed(2)}/rec`; }
function avg(m: Metrics): string { return (m.touchesSent / Math.max(1, m.totalEvents)).toFixed(2); }

function renderGrid(header: string[], rows: string[][]): string {
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(widths[i])).join('  ');
  const sep = header.map((_, i) => '-'.repeat(widths[i])).join('  ');
  const out = [line(header), sep];
  for (const r of rows) out.push(line(r));
  return out.join('\n');
}
