// External anchor for the audit hash chain.
//
// A raw hash chain is tamper-evident against editing a log AFTER the fact, but
// someone with write access to the whole log can regenerate a consistent fake
// chain from scratch. The fix is an EXTERNAL anchor: periodically publish the
// current chain root hash to a separate, append-only / write-once store (an
// external object store, a blockchain-ish notary, or in production a service the
// recovery engine does NOT control). Because the anchor lives outside the log,
// a rebuilt chain will no longer match the already-published roots.
//
// This module models the anchor *protocol* and stays honest that the durable
// sink is injected (see Sink). The core guarantee we prove here: an anchor
// published at time T commits the exact chain tail at T, and a later check
// against a different (rebuilt) chain line fails.

import { createHash } from 'crypto';
import { HashedEntry, GENESIS_HASH } from '../audit/chain';

// A minimal append-only sink. In production this is an external write-once
// service; here a Map-backed impl keeps the tests hermetic while keeping the
// interface identical to a real append-only store.
export interface AnchorSink {
  append(anchor: PublishedAnchor): void;
  all(): PublishedAnchor[];
  // latest() is the last-published root the engine would re-confirm against.
  latest(): PublishedAnchor | null;
}

export interface PublishedAnchor {
  createdAtMs: number;
  chainTailHash: string; // hash() of the last log entry at publish time
  root: string; // sha256(prevRoot + chainTailHash); GENESIS_ANCHOR for the first
}

export const GENESIS_ANCHOR = '0'.repeat(64);

export class MemoryAnchorSink implements AnchorSink {
  private store: PublishedAnchor[] = [];
  append(a: PublishedAnchor) { this.store.push(a); }
  all(): PublishedAnchor[] { return [...this.store]; }
  latest(): PublishedAnchor | null { return this.store.length ? this.store[this.store.length - 1] : null; }
}

// Publish the current chain tail as a new anchor.
export function publishAnchor(log: readonly HashedEntry[], sink: AnchorSink, createdAtMs?: number): PublishedAnchor {
  const chainTailHash = log.length ? log[log.length - 1].hash : GENESIS_HASH;
  const prevRoot = sink.latest()?.root ?? GENESIS_ANCHOR;
  const root = createHash('sha256').update(prevRoot + chainTailHash, 'utf8').digest('hex');
  const anchor: PublishedAnchor = {
    createdAtMs: createdAtMs ?? Date.now(),
    chainTailHash,
    root,
  };
  sink.append(anchor);
  return anchor;
}

export interface AnchorCheck {
  consistent: boolean;
  latestRoot: string | null;
  computedRoot: string | null;
  reason?: string;
}

// Reconfirm the CURRENT log tail against the most recently published anchor.
// If the engine (or an attacker) rebuilt the chain, either the tail hash or the
// chained root will no longer match the immutable published value.
export function verifyAnchor(log: readonly HashedEntry[], sink: AnchorSink): AnchorCheck {
  const latest = sink.latest();
  if (!latest) return { consistent: false, latestRoot: null, computedRoot: null, reason: 'no_anchor_published' };
  const computedTail = log.length ? log[log.length - 1].hash : GENESIS_HASH;
  if (computedTail !== latest.chainTailHash) {
    return { consistent: false, latestRoot: latest.root, computedRoot: null, reason: 'tail_hash_mismatch' };
  }
  // Recompute the root chain from the first anchor to the latest to prove the
  // published root equals what the current log implies.
  let recomputed = GENESIS_ANCHOR;
  for (const a of sink.all()) {
    recomputed = createHash('sha256').update(recomputed + a.chainTailHash, 'utf8').digest('hex');
  }
  if (recomputed !== latest.root) {
    return { consistent: false, latestRoot: latest.root, computedRoot: recomputed, reason: 'root_chain_mismatch' };
  }
  return { consistent: true, latestRoot: latest.root, computedRoot: recomputed };
}
