import { describe, it, expect, beforeAll } from 'vitest';
import { loadEvents } from '../src/batch/runner';
import {
  runSandbox,
  runScenario,
  countLockedViolations,
  SandboxReport,
} from '../src/policy/sandbox';
import { DEFAULT_TUNABLES } from '../src/policy/config';
import { getTunables, resetTunables } from '../src/decisions/rules';

const now = Date.UTC(2026, 8, 1, 14, 30);

describe('backtest sandbox', () => {
  const events = loadEvents().sort((a, b) => a.eventId.localeCompare(b.eventId));
  let report: SandboxReport;

  beforeAll(() => {
    report = runSandbox(events, { now });
  });

  it('always restores defaults after a scenario (no leaked tunables)', () => {
    resetTunables();
    expect(getTunables()).toEqual(DEFAULT_TUNABLES);
  });

  it('returns a baseline plus the swept scenarios', () => {
    expect(report.scenarios.length).toBeGreaterThanOrEqual(3);
    expect(report.baseline.recoveryRate).toBeGreaterThan(0);
  });

  it('locked safety/compliance rules never violate in any scenario', () => {
    expect(report.lockedInvariant).toBe(true);
    for (const s of report.scenarios) {
      const total = Object.values(s.lockedViolations).reduce((a, b) => a + b, 0);
      expect(total).toBe(0);
    }
  });

  it('tunables actually move recovery vs conservative tail', () => {
    const aggressive = report.scenarios.find((s) => s.scenarioLabel === 'aggressive');
    const conservative = report.scenarios.find((s) => s.scenarioLabel === 'conservative');
    expect(aggressive).toBeTruthy();
    expect(conservative).toBeTruthy();
    // Aggressive config grants more retries -> at least as much recovery & touches
    expect(aggressive!.metrics.touchesSent).toBeGreaterThanOrEqual(conservative!.metrics.touchesSent);
  });

  it('produces a headline mentioning the locked-rule invariant', () => {
    expect(report.headline).toContain('locked');
  });

  it('countLockedViolations reports zero even on extreme aggression', () => {
    const res = runScenario(
      events,
      now,
      'extreme',
      { maxRetryAttempts: 20, maxTouchesPerCustomer: 20, maxVoiceCalls: 20 },
      'data/test.sandbox.extreme.log.jsonl',
    );
    const total = Object.values(res.lockedViolations).reduce((a, b) => a + b, 0);
    expect(total).toBe(0);
  });
});
