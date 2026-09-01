// Tamper-evident hash chain over the append-only audit log.
// ADDITIVE ONLY: we do not change the existing entry schema — we append two
// new fields (prevHash, hash) to every entry. Each entry's hash commits to the
// previous entry's hash, forming a chain that makes any edit detectable.

import { createHash } from 'crypto';
import { AuditEntry } from '../flows/types';

export const GENESIS_HASH = '0'.repeat(64);

// Stable key-sorted stringify so the hash is reproducible regardless of how the
// object was constructed (key insertion order). ALWAYS excludes prevHash/hash
// so the hash does not self-reference, even if the object still carries them.
export function stableStringifyEntry(entry: Omit<AuditEntry, 'prevHash' | 'hash'>): string {
  const clone: Record<string, unknown> = {};
  for (const key of Object.keys(entry).sort()) {
    if (key === 'prevHash' || key === 'hash') continue;
    const value = (entry as unknown as Record<string, unknown>)[key];
    if (value !== undefined) clone[key] = value;
  }
  return JSON.stringify(clone);
}

// The data actually committed by the hash: every field except the two hash fields.
function hashPayload(entry: AuditEntry): string {
  const { prevHash: _p, hash: _h, ...rest } = entry;
  return stableStringifyEntry(rest);
}

export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// Compute an entry's hash given its prevHash. prevHash must equal the prior
// entry's hash (or GENESIS_HASH for the first entry).
export function computeHash(prevHash: string, entry: Omit<AuditEntry, 'prevHash' | 'hash'>): string {
  return sha256(prevHash + stableStringifyEntry(entry));
}

export interface HashedEntry extends AuditEntry {
  prevHash: string;
  hash: string;
}

// Pure: given the log tail and new entry data, return the log with the new
// hashed entry appended. Does NOT mutate the input array.
export function appendAuditEntry(
  log: readonly HashedEntry[],
  newEntryData: Omit<AuditEntry, 'prevHash' | 'hash'>,
): HashedEntry[] {
  const prevHash = log.length > 0 ? log[log.length - 1].hash : GENESIS_HASH;
  const hash = computeHash(prevHash, newEntryData);
  return [...log, { ...newEntryData, prevHash, hash }];
}

export interface ChainVerification {
  valid: boolean;
  brokenAtIndex: number | null;
  entries: number;
}

// Recompute the entire chain from scratch. Returns the first broken index
// (or null if the whole chain verifies).
export function verifyChain(log: readonly AuditEntry[]): ChainVerification {
  for (let i = 0; i < log.length; i++) {
    const entry = log[i] as HashedEntry;
    const expectedPrev = i === 0 ? GENESIS_HASH : (log[i - 1] as HashedEntry).hash;

    if (entry.prevHash !== expectedPrev) {
      return { valid: false, brokenAtIndex: i, entries: log.length };
    }
    const recomputed = computeHash(entry.prevHash, entry);
    if (entry.hash !== recomputed) {
      return { valid: false, brokenAtIndex: i, entries: log.length };
    }
  }
  return { valid: true, brokenAtIndex: null, entries: log.length };
}
