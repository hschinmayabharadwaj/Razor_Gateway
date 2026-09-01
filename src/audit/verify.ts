// CLI: npm run verify:audit
// Loads the batch run's audit log and verifies the tamper-evident hash chain.
// Prints ✓ verified, or ✗ the first broken index with details.

import * as fs from 'fs';
import * as path from 'path';
import { AuditEntry } from '../flows/types';
import { HashedEntry, verifyChain, computeHash, GENESIS_HASH } from './chain';

function main() {
  const file = path.join(process.cwd(), 'data', 'audit.log.jsonl');
  if (!fs.existsSync(file)) {
    console.error('No audit log found. Run `npm run run:batch` first.');
    process.exit(1);
  }
  const lines = fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0);
  const log = lines.map((l) => JSON.parse(l) as AuditEntry);

  const result = verifyChain(log);

  if (result.valid) {
    console.log(`✓ chain verified, ${result.entries} entries, no tampering detected`);
  } else {
    const idx = result.brokenAtIndex as number;
    const entry = log[idx] as HashedEntry;
    const expectedPrev = idx === 0 ? GENESIS_HASH : (log[idx - 1] as HashedEntry).hash;
    const recomputed = computeHash(entry.prevHash, entry);
    const what =
      entry.prevHash !== expectedPrev
        ? `prevHash mismatch (expected ${expectedPrev.slice(0, 16)}…, got ${entry.prevHash.slice(0, 16)}…)`
        : `hash mismatch (expected ${computeHashUsage(entry, recomputed)})`;
    console.log(`✗ chain broken at entry ${idx} (${entry.eventId ?? '?'}): ${what}`);
    process.exit(1);
  }
}

function computeHashUsage(entry: HashedEntry, recomputed: string): string {
  return `expected ${recomputed.slice(0, 16)}…, got ${entry.hash.slice(0, 16)}…`;
}

main();
