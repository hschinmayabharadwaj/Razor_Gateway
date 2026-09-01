import { describe, it, expect, beforeAll } from 'vitest';
import { deriveHistory, computePrescoreReport, emitPrescoreAudit, PrescoreReport } from '../src/risk/prescore';
import {
  riskScore as rawRiskScore,
  computeRiskFactors,
  isHighRisk,
  RISK_THRESHOLD_HIGH,
} from '../src/risk/riskScore';
import { FlowEvent } from '../src/flows/types';
import { createAuditStore } from '../src/audit/store';
import { runBatch, loadEvents } from '../src/batch/runner';
import { verifyChain } from '../src/audit/chain';

// ---- pure riskScore: named factors ----
describe('riskScore factors', () => {
  it('scores high on prior declines + recent failure', () => {
    const s = rawRiskScore({
      history: {
        priorDeclineCount90d: 3,
        mandateAgeDays: 10,
        daysSinceLastDecline: 1,
        priorChargebackCount90d: 1,
      },
    });
    expect(s.decision).toBe('high');
    expect(isHighRisk(s)).toBe(true);
    expect(s.factors.length).toBeGreaterThanOrEqual(3);
    // named factors are inspectable
    const keys = s.factors.map((f) => f.key);
    expect(keys).toContain('prior_decline_count_90d');
    expect(keys).toContain('days_since_last_decline');
    expect(keys).toContain('mandate_age_days');
  });

  it('scores low on clean history', () => {
    const s = rawRiskScore({
      history: {
        priorDeclineCount90d: 0,
        mandateAgeDays: 200,
        daysSinceLastDecline: 60,
        priorChargebackCount90d: 0,
      },
    });
    expect(s.decision).toBe('low');
    expect(isHighRisk(s)).toBe(false);
  });

  it('adds explicit card-expiry factor when within 60d', () => {
    const factors = computeRiskFactors({
      priorDeclineCount90d: 0,
      mandateAgeDays: 200,
      daysSinceLastDecline: 60,
      priorChargebackCount90d: 0,
      cardExpiresWithinDays: 20,
    });
    expect(factors.some((f) => f.key === 'card_expiry_within_60d')).toBe(true);
  });

  it('is clamped within 0..100', () => {
    const s = rawRiskScore({
      history: {
        priorDeclineCount90d: 99,
        mandateAgeDays: 0,
        daysSinceLastDecline: 0,
        priorChargebackCount90d: 99,
      },
    });
    expect(s.score).toBeLessThanOrEqual(100);
    expect(s.score).toBeGreaterThanOrEqual(0);
  });

  it('derived history is deterministic for the same customer', () => {
    const ev = { customerId: 'cust_abc_00042', signal: { error_reason: 'expired_card' } } as FlowEvent;
    expect(deriveHistory(ev)).toEqual(deriveHistory(ev));
  });
});

// ---- full batch prescore report ----
describe('prescore report over real batch', () => {
  const now = Date.UTC(2026, 8, 1, 14, 30);
  let report: PrescoreReport;
  let eventsForEmit: FlowEvent[];

  beforeAll(() => {
    eventsForEmit = loadEvents().sort((a, b) => a.eventId.localeCompare(b.eventId));
    const audit = createAuditStore('data/test.prescore.log.jsonl');
    audit.clear();
    runBatch(eventsForEmit, audit, { now });
    report = computePrescoreReport(eventsForEmit, audit.all());
  });

  it('produces a row per event with a bounded score', () => {
    expect(report.totalEvents).toBe(eventsForEmit.length);
    for (const r of report.rows) {
      expect(r.score).toBeGreaterThanOrEqual(0);
      expect(r.score).toBeLessThanOrEqual(100);
      expect(r.highRiskBefore).toBe(r.score >= RISK_THRESHOLD_HIGH);
    }
  });

  it('classifies every event as either recovered or failed', () => {
    for (const r of report.rows) expect(r.recovered || r.failedToRecover).toBe(true);
  });

  it('emits hash-chained prescore audit entries that verify', () => {
    const audit = createAuditStore('data/test.prescore.emit.log.jsonl');
    audit.clear();
    runBatch(eventsForEmit, audit, { now });
    emitPrescoreAudit(report, audit);
    const check = verifyChain(audit.all());
    expect(check.valid).toBe(true);
    expect(check.entries).toBeGreaterThan(eventsForEmit.length);
  });

  it('produces a non-trivial headline referencing recall and precision', () => {
    expect(report.headline).toContain('%');
    expect(typeof report.recall).toBe('number');
    expect(typeof report.precision).toBe('number');
  });
});
