// CLI: Prevention layer demo. Runs the real batch, then computes the retroactive
// risk-prescore report over the same events, comparing pre-score to actual
// outcome. Also appends the prescores to the (hash-chained) audit log and
// verifies the chain still holds afterward.

import { createAuditStore } from './audit/store';
import { runBatch } from './batch/runner';
import { loadEvents } from './batch/runner';
import { verifyChain } from './audit/chain';
import { computePrescoreReport, renderPrescoreReport, emitPrescoreAudit } from './risk/prescore';

function main() {
  const now = Date.UTC(2026, 8, 1, 14, 30);
  const events = loadEvents().sort((a, b) => a.eventId.localeCompare(b.eventId));

  const realStore = createAuditStore('data/audit.prescore.base.log.jsonl');
  realStore.clear();
  runBatch(events, realStore, { now });

  // Compute prescore BEFORE outcomes are known conceptually — but we're drawing
  // the audit entries that encode the actual outcome afterward. This simulates
  // a backtest: we knew the score first, and the outcome arrived later.
  const report = computePrescoreReport(events, realStore.all());

  // Append prescores to the same hash-chained log, then prove it still verifies.
  const audit = createAuditStore('data/audit.prescore.log.jsonl');
  audit.clear();
  // Re-run the real policy so the chain starts fresh, then layer prescores in.
  runBatch(events, audit, { now });
  const emitted = emitPrescoreAudit(report, audit);

  const check = verifyChain(audit.all());
  const all = audit.all();

  console.log(renderPrescoreReport(report));
  console.log('');
  console.log(`Prescore entries appended: ${emitted} | total log: ${all.length}`);
  console.log(
    check.valid
      ? `✓ chain verified: ${all.length} entries, no tampering detected`
      : `✗ CHAIN BROKEN at entry ${check.brokenAtIndex}`,
  );
}

main();
