// Plain-text functional dashboard rendered from the audit log.
// Table view + metrics + per-flow breakdown + exception list.

import { AuditEntry, FLOW_TYPES, AgentState } from '../flows/types';
import { Metrics } from '../metrics';

export function renderTable(log: AuditEntry[]): string {
  const terminal = new Map<string, AuditEntry>();
  const lifecycle = new Map<string, string[]>();
  for (const e of log) {
    const arr = lifecycle.get(e.eventId) ?? [];
    arr.push(`${symbol(e.state)} ${e.decision}(${e.ruleFired}/${e.actor})`);
    lifecycle.set(e.eventId, arr);
    if (isTerminal(e.state)) terminal.set(e.eventId, e);
  }

  const header = ['event_id', 'flow', 'reason', 'INR', 'touches', 'lifecycle'];
  const rows: string[][] = [];
  for (const [id, e] of terminal) {
    const touches = lifecycle.get(id)!.filter((s) => s.includes(':retry') || s.includes(':contact')).length;
    rows.push([
      id,
      e.flow,
      e.reasonBucket,
      ((e.amount ?? 0) / 100).toFixed(0),
      String(touches),
      lifecycle.get(id)!.join(' > '),
    ]);
  }
  return renderGrid(header, rows);
}

export function renderMetrics(m: Metrics): string {
  const out: string[] = [];
  out.push('');
  out.push('===== METRICS (computed from audit log) =====');
  out.push(`Total at-risk:       ₹${m.totalAtRiskRupees.toFixed(2)}`);
  out.push(`Recovered:           ₹${m.recoveredRupees.toFixed(2)}`);
  out.push(`Recovery rate:       ${(m.recoveryRate * 100).toFixed(1)}%`);
  out.push(`Touches sent:        ${m.touchesSent}`);
  out.push(`Recovered count:     ${m.recoveredCount}`);
  out.push(`Cost per recovery:   ${m.costPerRecovery.toFixed(2)} touches/recovery`);
  out.push(`Escalated:           ${m.escalatedCount}`);
  out.push(`Abandoned:           ${m.abandonedCount}`);
  out.push(`Suppressed:          ${m.suppressedCount}`);
  out.push('');
  out.push('===== BREAKDOWN BY FLOW =====');
  const h = ['flow', 'events', 'recovered', 'recovered(INR)', 'esc', 'sup', 'abn', 'touches'];
  const r: string[][] = FLOW_TYPES.map((f) => {
    const d = m.byFlow[f];
    return [
      f,
      String(d.events),
      String(d.recoveredCount),
      d.recoveredRupees.toFixed(0),
      String(d.escalated),
      String(d.suppressed),
      String(d.abandoned),
      String(d.touches),
    ];
  });
  out.push(renderGrid(h, r));
  out.push('');
  out.push('===== EXCEPTION LIST (escalated / abandoned / waiting_on_ptp) =====');
  if (m.exceptionList.length === 0) {
    out.push('  (none)');
  } else {
    const eh = ['event_id', 'flow', 'customer', 'invoice', 'reason', 'status', 'INR', 'rule'];
    const er: string[][] = m.exceptionList.map((e) => [
      e.eventId, e.flow, e.customerId, e.invoiceId, e.reason, e.status,
      e.amountInRupees.toFixed(0), e.ruleFired,
    ]);
    out.push(renderGrid(eh, er));
  }
  return out.join('\n');
}

function symbol(s: string): string {
  switch (s) {
    case 'recovered': return 'R';
    case 'escalated': return 'E';
    case 'abandoned': return 'A';
    case 'suppressed': return 'S';
    case 'retry_scheduled': return 's';
    case 'retrying': return 'r';
    case 'contact_scheduled': return 'c';
    case 'contacting': return 'C';
    case 'waiting_on_ptp': return 'P';
    case 'diagnosed': return 'd';
    default: return '?';
  }
}

function isTerminal(s: AgentState | string): boolean {
  return s === 'recovered' || s === 'escalated' || s === 'abandoned' || s === 'suppressed';
}

function renderGrid(header: string[], rows: string[][]): string {
  const widths = header.map((hh, i) => Math.max(hh.length, ...rows.map((rr) => (rr[i] ?? '').length)));
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(widths[i])).join('  ');
  const sep = header.map((_, i) => '-'.repeat(widths[i])).join('  ');
  const out = [line(header), sep];
  for (const rr of rows) out.push(line(rr));
  return out.join('\n');
}
