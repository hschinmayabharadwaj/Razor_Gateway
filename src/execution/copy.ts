// LLM copy generation — the ONLY allowed LLM seam.
// It NEVER decides whether to retry/stop/escalate; it only formats human-facing
// text AFTER the policy engine has decided. Deterministic templates provided for
// tests/demo; a real model swaps in at this single boundary.

import { FlowType, ReasonBucket } from '../flows/types';

export interface CopyInput {
  eventId: string;
  flow: FlowType;
  customerName: string;
  customerEmail?: string;
  amountInRupees: number;
  reason: ReasonBucket;
  invoiceId?: string;
  overdueDays?: number;
  channel?: string;
}

export interface MessageCopy {
  subject: string;
  body: string;
  channel: string;
  producer: 'llm';
}

const SUBJECT: Record<FlowType, (r: ReasonBucket, amt: number) => string> = {
  failed_subscription: () => 'Your renewal failed — quick fix needed',
  checkout_abandonment: () => 'You left something in your cart',
  b2b_receivables: (r) => (r === 'disputed_receivable' ? 'Invoice query received' : 'Invoice #{invoice} due'),
  payment_degradation: () => 'Payment success rate alert',
  mandate_retry: () => 'Autopay retry scheduled',
  hinglish_voice: () => 'Recovery call — aapka payment pending hai',
  promise_to_pay: () => 'Your payment promise reminder',
};

const BODY_SUBJECT: Record<FlowType, string> = {
  failed_subscription: 'renewal failed',
  checkout_abandonment: 'left cart items behind',
  b2b_receivables: 'overdue invoice',
  payment_degradation: 'payment degradation',
  mandate_retry: 'autopay retry',
  hinglish_voice: 'payment pending',
  promise_to_pay: 'payment promise',
};

// Produces a templated message for ANY flow. This is what a model would replace.
export function generateCopy(input: CopyInput): MessageCopy {
  const subject = SUBJECT[input.flow](input.reason, input.amountInRupees);
  const body = templatedBody(input);
  return { subject, body, channel: input.channel ?? 'email', producer: 'llm' };
}

function templatedBody(input: CopyInput): string {
  const who = input.customerName;
  const amt = `₹${input.amountInRupees.toFixed(2)}`;
  switch (input.flow) {
    case 'hinglish_voice':
      return `Namaste ${who}! Aapke renewal ka paisa ${amt} pending hai. Ek baar payment kar dijiye, sab set ho jayega. Dhanyavaad!`;
    case 'checkout_abandonment':
      return `Hi ${who}, you left items worth ${amt} in your cart. Complete your order and we'll hold them for you.`;
    case 'b2b_receivables':
      return `Dear ${who}, invoice #${input.invoiceId ?? ''} of ${amt} is overdue by ${input.overdueDays ?? 0} days. Please arrange payment.`;
    case 'payment_degradation':
      return `Hi team, payment success rate dropped below threshold near ${input.eventId}. Recommend reviewing the payment gateway config.`;
    case 'mandate_retry':
      return `Hi ${who}, we scheduled an autopay retry for ${amt}. No action needed unless it fails again.`;
    case 'promise_to_pay':
      return `Hi ${who}, this is a reminder about your payment promise of ${amt}.`;
    case 'failed_subscription':
    default:
      return `Hi ${who}, your subscription renewal of ${amt} could not be completed (${input.reason}). Please update your payment method.`;
  }
}

// Summarize exceptions for a human reviewer (LLM allowed here too).
export interface ExceptionSummaryCopy {
  text: string;
  producer: 'llm';
}

export function generateExceptionSummary(
  exceptions: { eventId: string; flow: FlowType; reason: ReasonBucket; amountInRupees: number }[],
): ExceptionSummaryCopy {
  const byFlow = exceptions.reduce<Record<string, number>>((acc, e) => {
    acc[e.flow] = (acc[e.flow] ?? 0) + 1;
    return acc;
  }, {});
  const lines = Object.entries(byFlow)
    .map(([f, n]) => `  - ${f}: ${n}`)
    .join('\n');
  const total = exceptions.reduce((s, e) => s + e.amountInRupees, 0);
  return {
    text: `Human Reviewer — ${exceptions.length} exceptions require manual action totalling ₹${total.toFixed(2)}.\nBy flow:\n${lines}\nReview each to resolve within the retry/promise window.`,
    producer: 'llm',
  };
}
