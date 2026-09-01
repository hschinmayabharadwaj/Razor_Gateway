import { describe, it, expect } from 'vitest';
import {
  GENESIS_HASH,
  appendAuditEntry,
  verifyChain,
  computeHash,
  sha256,
} from '../src/audit/chain';
import { AuditEntry, RuleId, Decision, Actor, AgentState, FlowType, ReasonBucket } from '../src/flows/types';

function baseEntry(over: Partial<AuditEntry> = {}): Omit<AuditEntry, 'prevHash' | 'hash'> {
  return {
    eventId: 'e1',
    timestamp: '2026-09-01T00:00:00.000Z',
    flow: 'failed_subscription',
    reasonBucket: 'insufficient_funds',
    ruleFired: 'transient_retry',
    decision: 'retry',
    actor: 'policy_engine',
    outcome: 'Scheduled retry',
    state: 'retry_scheduled',
    ...over,
  };
}

describe('Hash chain primitives', () => {
  it('GENESIS_HASH is 64 zeros', () => {
    expect(GENESIS_HASH).toBe('0'.repeat(64));
    expect(GENESIS_HASH.length).toBe(64);
  });
  it('sha256 returns a 64-hex-char digest', () => {
    expect(sha256('hello')).toMatch(/^[0-9a-f]{64}$/);
  });
  it('stableStringify produces identical output regardless of key order', () => {
    const a = computeHash(GENESIS_HASH, baseEntry({ attempt: 1, amount: 100 }));
    const b = computeHash(GENESIS_HASH, baseEntry({ attempt: 1, amount: 100 }));
    expect(a).toBe(b);
  });
  it('hash changes when any content field changes', () => {
    const h1 = computeHash(GENESIS_HASH, baseEntry());
    const h2 = computeHash(GENESIS_HASH, baseEntry({ decision: 'escalate' }));
    expect(h1).not.toBe(h2);
  });
});

describe('appendAuditEntry (pure)', () => {
  it('does not mutate the input array', () => {
    const log: any[] = [];
    const next = appendAuditEntry(log, baseEntry());
    expect(log.length).toBe(0);
    expect(next.length).toBe(1);
    const next2 = appendAuditEntry(next, baseEntry({ eventId: 'e2' }));
    expect(next.length).toBe(1); // original still intact
    expect(next2.length).toBe(2);
  });
  it('first entry uses GENESIS_HASH as prevHash', () => {
    const [first] = appendAuditEntry([], baseEntry());
    expect(first.prevHash).toBe(GENESIS_HASH);
    expect(first.hash).toBe(computeHash(GENESIS_HASH, first));
  });
  it('each entry links to the previous hash', () => {
    let log: any[] = [];
    log = appendAuditEntry(log, baseEntry());
    log = appendAuditEntry(log, baseEntry({ eventId: 'e2' }));
    log = appendAuditEntry(log, baseEntry({ eventId: 'e3' }));
    expect(log[1].prevHash).toBe(log[0].hash);
    expect(log[2].prevHash).toBe(log[1].hash);
  });
});

describe('verifyChain', () => {
  it('validates a correctly-built 5-entry chain', () => {
    let log: any[] = [];
    for (let i = 0; i < 5; i++) {
      log = appendAuditEntry(log, baseEntry({ eventId: `e${i}`, attempt: i }));
    }
    const res = verifyChain(log);
    expect(res.valid).toBe(true);
    expect(res.brokenAtIndex).toBeNull();
    expect(res.entries).toBe(5);
  });

  it('detects tampering of a field deep in the chain (entry[2] decision)', () => {
    let log: any[] = [];
    for (let i = 0; i < 5; i++) {
      log = appendAuditEntry(log, baseEntry({ eventId: `e${i}`, attempt: i }));
    }
    // Simulate an attacker rewriting entry 2's decision without recomputing hashes.
    log[2] = { ...log[2], decision: 'escalate' };

    const res = verifyChain(log);
    expect(res.valid).toBe(false);
    expect(res.brokenAtIndex).toBe(2);
  });

  it('detects an altered prevHash link', () => {
    let log: any[] = [];
    for (let i = 0; i < 3; i++) log = appendAuditEntry(log, baseEntry({ eventId: `e${i}` }));
    log[1] = { ...log[1], prevHash: 'x'.repeat(64) };
    const res = verifyChain(log);
    expect(res.valid).toBe(false);
    expect(res.brokenAtIndex).toBe(1);
  });
});
