// Synthetic batch generator for ALL 7 recovery flows.
// Writes normalized FlowEvents to data/flows/*.json (one per event).
// Deterministic PRNG so the demo is reproducible.

import * as fs from 'fs';
import * as path from 'path';
import { FlowEvent, FlowType } from '../flows/types';

function mulberry32(seed: number) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(20260201);

function pick<T>(arr: readonly T[]): T { return arr[Math.floor(rng() * arr.length)]; }
function int(min: number, max: number): number { return Math.floor(rng() * (max - min + 1)) + min; }

const FIRST = ['Aarav', 'Diya', 'Rohan', 'Meera', 'Kabir', 'Ananya', 'Vihaan', 'Sara', 'Arjun', 'Ishaan', 'Zoya', 'Reyansh', 'Aisha', 'Vivaan'];
const LAST = ['Sharma', 'Patel', 'Reddy', 'Iyer', 'Nair', 'Gupta', 'Singh', 'Verma', 'Rao', 'Menon', 'Joshi', 'Mehta'];
const EMAILS = ['gmail.com', 'yahoo.com', 'outlook.com'];

const NOW = Date.UTC(2026, 8, 1); // Sept 1 2026

function name(): { name: string; email: string } {
  const n = `${pick(FIRST)} ${pick(LAST)}`;
  const email = `${n.toLowerCase().replace(/\s+/g, '.')}${int(1, 99)}@${pick(EMAILS)}`;
  return { name: n, email };
}

let seq = 0;
const events: FlowEvent[] = [];
function emit(flow: FlowType, amount: number, overrides: Partial<FlowEvent> = {}): void {
  seq++;
  const base = name();
  events.push({
    eventId: `${flow}-${seq.toString().padStart(5, '0')}`,
    flow,
    customerId: `cust_${flow.slice(0, 3)}_${seq}`,
    customerName: base.name,
    customerEmail: base.email,
    customerPhone: `+91 9${int(5000, 9999)}${int(10000, 99999)}`,
    amount,
    currency: 'INR',
    occurredAt: NOW - int(0, 7) * 86400000,
    invoiceId: `inv_${seq.toString().padStart(8, '0')}`,
    ...overrides,
  });
}

// ---------- Flow 1: payment_degradation ----------
// rolling success rate below threshold, latency spike, issuer down cases
for (let i = 0; i < 8; i++) {
  const kind = i % 3;
  const rate = kind === 0 ? 0.8 - rng() * 0.1 : 0.98;
  emit('payment_degradation', int(100000, 900000), {
    signal: {
      success_rate: rate,
      latency_ms: kind === 1 ? 3000 + int(0, 2000) : int(200, 800),
      issuer_down: kind === 2 ? true : false,
      error_code: kind === 2 ? 'ISSUER_DOWN' : 'SUCCESS_RATE_DROP',
      recovered: true,
    },
  });
}

// ---------- Flow 2: checkout_abandonment ----------
// mixed: repeat vs one-time visitors, payment/address step, price mismatch
for (let i = 0; i < 10; i++) {
  const step = pick(['payment', 'address', 'otp', 'complete'] as const);
  const visits = int(1, 5);
  const priceMismatch = i % 5 === 0;
  emit('checkout_abandonment', int(50000, 1500000), {
    signal: {
      abandoned_at_step: step,
      cart_value: int(50000, 1500000),
      visits,
      price_mismatch: priceMismatch,
      error: step === 'complete' ? 'gateway_timeout' : '',
    },
  });
}

// ---------- Flow 3: failed_subscription (Razorpay) ----------
const SUB_ERRORS: [string, string, string, string][] = [
  ['BAD_REQUEST_ERROR', 'CARD_DECLINED', 'insufficient funds', 'neg_bank'],
  ['CARD_EXPIRED', 'CARD_EXPIRED', 'expired', 'expired_card'],
  ['MANDATE_REVOKED', 'MANDATE_REVOKED', 'mandate revoked', 'mandate_revoked_by_customer'],
  ['ISSUER_UNAVAILABLE', 'NETWORK_ERROR', 'temporarily unavailable', 'transient_failure'],
  ['AUTH_FAILED', 'CUSTOMER_ABANDONED', '3DS abandoned', 'otp_timeout'],
  ['FRAUD_DETECTED', 'RISK_DECLINE', 'flagged fraud', 'risk_decline'],
];
const SUB_BUCKETS = ['insufficient_funds', 'card_expired', 'mandate_revoked', 'bank_declined_transient', 'auth_3ds_abandoned', 'fraud_flagged'];
for (let i = 0; i < 12; i++) {
  const b = SUB_BUCKETS[i % SUB_BUCKETS.length];
  const e = SUB_ERRORS[i % SUB_ERRORS.length];
  emit('failed_subscription', int(49900, 9990000), {
    signal: { error_code: e[0], error_description: e[2], error_reason: e[3], payment_method: pick(['card', 'upi', 'emandate']), mandate_revoked: b === 'mandate_revoked' },
  });
}

// ---------- Flow 4: b2b_receivables ----------
// overdue tiers net30, net60, disputed
for (let i = 0; i < 10; i++) {
  const disputed = i % 3 === 0;
  const days = disputed ? 35 : pick([25, 40, 45, 65, 75, 90, 130, 10] as number[]);
  emit('b2b_receivables', int(500000, 9000000), {
    signal: { overdue_days: days, disputed, dispute_note: disputed ? 'Billing dispute filed' : '' },
  });
}

// ---------- Flow 5: mandate_retry (NPCI / UPI Autopay) ----------
// retry-window bounded sequencing; some mandates revoked
for (let i = 0; i < 8; i++) {
  const revoked = i % 4 === 0;
  const windowStart = NOW - 86400000;
  emit('mandate_retry', int(100000, 5000000), {
    signal: {
      error_code: revoked ? 'MANDATE_REVOKED' : int(0, 1) ? 'ISSUER_UNAVAILABLE' : 'BAD_REQUEST_ERROR',
      retry_window: { start: windowStart, end: windowStart + 3 * 86400000 },
      mandate_revoked: revoked,
    },
  });
}

// ---------- Flow 6: hinglish_voice ----------
// missed call, callback requested, unreachable, DNC flag
for (let i = 0; i < 6; i++) {
  const state = pick(['missed', 'call_back_requested', 'unreachable'] as const);
  emit('hinglish_voice', int(20000, 4000000), {
    signal: { call_state: state, dnc_flag: i === 3, hour: i === 4 ? 22 : 14 },
  });
}

// ---------- Flow 7: promise_to_pay ----------
// committed (future PTP date), missed, broken
for (let i = 0; i < 6; i++) {
  const status = pick(['committed', 'committed', 'missed', 'broken'] as const);
  const ptpDate = status === 'committed' ? NOW + int(1, 4) * 86400000 : status === 'missed' ? NOW - 86400000 : NOW - 2 * 86400000;
  emit('promise_to_pay', int(50000, 5000000), {
    signal: { ptp_status: status, ptp_date: ptpDate, amount: int(50000, 5000000) },
  });
}

// Write
const outDir = path.join(process.cwd(), 'data', 'flows');
fs.mkdirSync(outDir, { recursive: true });
for (const e of events) {
  fs.writeFileSync(path.join(outDir, `${e.eventId}.json`), JSON.stringify(e, null, 2));
}
const byFlow = events.reduce<Record<string, number>>((a, e) => { a[e.flow] = (a[e.flow] ?? 0) + 1; return a; }, {});
console.log(`Wrote ${events.length} flow events to ${outDir}`);
console.log(JSON.stringify(byFlow, null, 2));
