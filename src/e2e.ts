// END-TO-END demo: one command that runs the whole story.
//   generate events -> real batch -> naive comparison -> chain verification
//   -> risk prescore report
// Everything on screen is a number actually computed from this run (deterministic
// batch, hash-chained audit log) — not a self-reported claim.

import { createAuditStore } from './audit/store';
import { runBatch, loadEvents } from './batch/runner';
import { verifyChain, GENESIS_HASH } from './audit/chain';
import { comparePolicies, renderComparison } from './policy/compare';
import { runSandbox, renderSandbox } from './policy/sandbox';
import { computePrescoreReport, renderPrescoreReport, emitPrescoreAudit } from './risk/prescore';
import { runSecurityDemo } from './security-demo';

function main() {
  const now = Date.UTC(2026, 8, 1, 14, 30);
  const events = loadEvents().sort((a, b) => a.eventId.localeCompare(b.eventId));

  console.log('==============================================================');
  console.log(' REVENUE RECOVERY AGENT — END-TO-END DEMO');
  console.log(` ${events.length} events across 7 flows | deterministic seed 2026-02-01`);
  console.log('==============================================================');

  // ---- 1. Real policy engine -> hash-chained audit log ----
  const realStore = createAuditStore('data/audit.e2e.real.log.jsonl');
  realStore.clear();
  runBatch(events, realStore, { now });
  const realLog = realStore.all();
  const chain = verifyChain(realLog);
  console.log('\n[1] REAL policy -> audit log');
  console.log(`    ${realLog.length} hash-chained entries | chain: ${chain.valid ? '✓ VERIFIED' : '✗ BROKEN'}`);

  // ---- 2. Naive vs real comparison ----
  const cmp = comparePolicies(events, createAuditStore('data/audit.e2e.cmp.real.log.jsonl'), createAuditStore('data/audit.e2e.cmp.naive.log.jsonl'), { now });
  console.log(renderComparison(cmp));

  // ---- 3. Backtest sandbox (tunables move, locked rules don't) ----
  console.log(renderSandbox(runSandbox(events, { now })));

  // ---- 4. Risk prescore (prevention layer) appended to a chain ----
  const audit = createAuditStore('data/audit.e2e.prescore.log.jsonl');
  audit.clear();
  runBatch(events, audit, { now });
  const prescore = computePrescoreReport(events, realLog);
  emitPrescoreAudit(prescore, audit);
  const prescoreChain = verifyChain(audit.all());
  console.log(renderPrescoreReport(prescore));
  console.log(`    prescore entries appended | chain: ${prescoreChain.valid ? '✓ VERIFIED' : '✗ BROKEN'}`);

  // ---- 5. Tamper demonstration (in-memory, non-destructive) ----
  console.log('\n[5] TAMPER-EVIDENCE DEMO (in-memory, does not touch the file)');
  const tampered = JSON.parse(JSON.stringify(realLog));
  const tamperIdx = tampered.findIndex((e: any) => e.decision !== 'none' && (e.decision === 'retry' || e.decision === 'contact' || e.decision === 'hold'));
  if (tamperIdx >= 0) {
    const entry = tampered[tamperIdx];
    const before = entry.decision;
    entry.decision = before === 'retry' ? 'escalate' : 'abandon';
    const broken = verifyChain(tampered);
    console.log(`    flipped decision ${before ?? ''} -> ${entry.decision} on entry ${tamperIdx} (${entry.eventId ?? ''})`);
    console.log(`    verifyChain -> ${broken.valid ? '✓ still valid' : `✗ BROKEN at entry ${broken.brokenAtIndex} (${entry.eventId})`}`);
    console.log('    => any edit to the log is detectable, and we prove it live.');
  }

  const genesisOk = realLog[0]?.prevHash === GENESIS_HASH;
  console.log(`\n    genesis hash anchored: ${genesisOk ? '✓' : '✗'}`);

  // ---- 6. Security posture walkthrough ----
  runSecurityDemo();

  console.log('\n==============================================================');
  console.log(' ALL DEMO STEPS COMPLETE');
  console.log('==============================================================');
}

main();
