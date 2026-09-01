import * as path from 'path';
import { createAuditStore } from './audit/store';
import { loadEvents } from './batch/runner';
import { comparePolicies, renderComparison } from './policy/compare';

function main() {
  const events = loadEvents();

  // Use the same daytime timestamp as the main batch for a fair comparison.
  const now = Date.UTC(2026, 8, 1, 14, 30);

  const realAudit = createAuditStore(path.join(process.cwd(), 'data', 'audit.real.jsonl'));
  const naiveAudit = createAuditStore(path.join(process.cwd(), 'data', 'audit.naive.jsonl'));

  const result = comparePolicies(events, realAudit, naiveAudit, { now });

  console.log(`Compared REAL vs NAIVE policy over ${events.length} identical synthetic events.\n`);
  console.log(renderComparison(result));
}

main();
