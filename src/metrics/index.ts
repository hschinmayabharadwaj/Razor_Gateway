// Metrics computed purely from the audit log (never asserted).
// Now flow-aware; supports overall and per-flow statistics.

import { AuditEntry, FlowType, ReasonBucket, FLOW_TYPES, AgentState } from '../flows/types';

export interface ExceptionItem {
  eventId: string;
  flow: FlowType;
  customerId: string;
  invoiceId: string;
  reason: ReasonBucket;
  status: 'escalated' | 'abandoned' | 'waiting_on_ptp';
  amountInRupees: number;
  ruleFired: string;
  outcome: string;
}

export interface FlowMetrics {
  events: number;
  recoveredCount: number;
  recoveredRupees: number;
  escalated: number;
  suppressed: number;
  abandoned: number;
  touches: number;
}

export interface Metrics {
  totalEvents: number;
  totalAtRiskRupees: number;
  recoveredCount: number;
  recoveredRupees: number;
  recoveryRate: number;
  touchesSent: number;
  costPerRecovery: number;
  escalatedCount: number;
  abandonedCount: number;
  suppressedCount: number;
  byFlow: Record<FlowType, FlowMetrics>;
  exceptionList: ExceptionItem[];
}

const TERMINAL = new Set<AgentState>(['recovered', 'escalated', 'abandoned', 'suppressed']);

function initFlow(): FlowMetrics {
  return { events: 0, recoveredCount: 0, recoveredRupees: 0, escalated: 0, suppressed: 0, abandoned: 0, touches: 0 };
}

export function computeMetrics(log: AuditEntry[]): Metrics {
  const byFlow = Object.fromEntries(FLOW_TYPES.map((f) => [f, initFlow()])) as Record<FlowType, FlowMetrics>;

  const terminal = new Map<string, AuditEntry>();
  const seen = new Set<string>();
  for (const e of log) {
    const f = byFlow[e.flow];
    if (!seen.has(e.eventId)) {
      f.events++;
      seen.add(e.eventId);
    }
    if (e.decision === 'retry' || e.decision === 'contact') f.touches++;
    if (TERMINAL.has(e.state)) terminal.set(e.eventId, e);
  }

  let recoveredCount = 0;
  let recoveredRupees = 0;
  let totalAtRisk = 0;
  for (const [, e] of terminal) {
    totalAtRisk += e.amount ?? 0;
    const f = byFlow[e.flow];
    if (e.state === 'recovered') {
      f.recoveredCount++;
      f.recoveredRupees += e.amount ?? 0;
      recoveredCount++;
      recoveredRupees += e.amount ?? 0;
    } else if (e.state === 'escalated') f.escalated++;
    else if (e.state === 'suppressed') f.suppressed++;
    else if (e.state === 'abandoned') f.abandoned++;
  }

  const exceptionList: ExceptionItem[] = [];
  for (const [, e] of terminal) {
    if (e.state === 'escalated' || e.state === 'abandoned' || e.state === 'waiting_on_ptp') {
      exceptionList.push({
        eventId: e.eventId,
        flow: e.flow,
        customerId: e.customerId ?? '',
        invoiceId: e.invoiceId ?? '',
        reason: e.reasonBucket,
        status: e.state,
        amountInRupees: (e.amount ?? 0) / 100,
        ruleFired: e.ruleFired,
        outcome: e.outcome,
      });
    }
  }
  exceptionList.sort((a, b) => (a.flow < b.flow ? -1 : a.flow > b.flow ? 1 : 0));

  const touchesSent = FLOW_TYPES.reduce((s, f) => s + byFlow[f].touches, 0);

  return {
    totalEvents: terminal.size,
    totalAtRiskRupees: totalAtRisk / 100,
    recoveredCount,
    recoveredRupees: recoveredRupees / 100,
    recoveryRate: totalAtRisk > 0 ? recoveredRupees / totalAtRisk : 0,
    touchesSent,
    costPerRecovery: recoveredCount > 0 ? touchesSent / recoveredCount : 0,
    escalatedCount: exceptionList.filter((e) => e.status === 'escalated').length,
    abandonedCount: exceptionList.filter((e) => e.status === 'abandoned').length,
    suppressedCount: [...terminal.values()].filter((e) => e.state === 'suppressed').length,
    byFlow,
    exceptionList,
  };
}
