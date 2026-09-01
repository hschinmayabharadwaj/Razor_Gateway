// CLI: Backtest sandbox demo. Runs the same 60-event batch under a sweep of
// tunable policies and shows recovery/violation metrics moving while the LOCKED
// safety rules never budge.

import { loadEvents } from './batch/runner';
import { runSandbox, renderSandbox } from './policy/sandbox';

const events = loadEvents().sort((a, b) => a.eventId.localeCompare(b.eventId));
const report = runSandbox(events);
console.log(renderSandbox(report));
