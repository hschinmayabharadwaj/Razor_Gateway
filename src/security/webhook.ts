// Webhook / inbound-event signature verification.
//
// Every event that enters the recovery pipeline from an external system (e.g.
// a Razorpay `subscription.charged.failed` webhook, checkout analytics, an ERP
// receivable extract) must be authenticated BEFORE it is trusted as an input.
//
// Razorpay signs webhook payloads with a scheme that carries both a timestamp
// and an HMAC-SHA256 signature:
//
//   Header:  X-Razorpay-Signature: t=<unix_seconds>|s=<hex_hmac_sha256>
//   Payload: HMAC_SHA256(secret, `${t}.${rawBody}`)
//
// We verify the signature AND check the timestamp is fresh (replay protection).
// Nothing downstream runs until verification passes.

import { createHmac, timingSafeEqual } from 'crypto';

export interface VerifiedWebhook {
  ok: boolean;
  eventId: string;
  flow: string;
  reason?: string; // when !ok
}

// Max age (seconds) a signed payload may be before we reject it as a replay.
export const MAX_WEBHOOK_SKEW_SECONDS = 300; // 5 min

function parseSignatureHeader(header: string | undefined): { t: number; s: string } | null {
  if (!header) return null;
  const parts = header.split('|').reduce<Record<string, string>>((acc, kv) => {
    const idx = kv.indexOf('=');
    if (idx > 0) acc[kv.slice(0, idx)] = kv.slice(idx + 1);
    return acc;
  }, {});
  const t = Number(parts['t']);
  const s = parts['s'];
  if (!Number.isFinite(t) || !s) return null;
  return { t, s };
}

// Constant-time compare to avoid timing side-channels.
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Compute the Razorpay-style signature for a payload + timestamp.
export function computeWebhookSignature(secret: string, t: number, rawBody: string): string {
  return createHmac('sha256', secret).update(`${t}.${rawBody}`).digest('hex');
}

// Verify a webhook. `secret` comes from config/env (see secrets.ts) — never a
// hard-coded value. `nowSeconds` injectable for deterministic tests.
export function verifyWebhook(
  secret: string,
  headers: Record<string, string | undefined>,
  rawBody: string,
  nowSeconds?: number,
): { ok: boolean; reason?: string } {
  const sig = parseSignatureHeader(
    headers['x-razorpay-signature'] ?? headers['X-Razorpay-Signature'],
  );
  if (!sig) return { ok: false, reason: 'missing_or_malformed_signature' };

  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - sig.t) > MAX_WEBHOOK_SKEW_SECONDS) {
    return { ok: false, reason: 'expired_signature_replay_rejected' };
  }

  const expected = computeWebhookSignature(secret, sig.t, rawBody);
  if (!safeEqual(expected, sig.s)) {
    return { ok: false, reason: 'signature_mismatch' };
  }
  return { ok: true };
}

// Convenience: verify the body, then extract the event id/flow from the trusted
// payload. Never call this with an unverified body; the classifer/batch must
// only ever see events that passed verifyWebhook.
export function parseTrustedEvent(rawBody: string): { eventId: string; flow?: string } | null {
  try {
    const parsed = JSON.parse(rawBody);
    const eventId: string | undefined = parsed?.event_id ?? parsed?.id;
    const flow: string | undefined = parsed?.flow ?? parsed?.entity?.type;
    if (!eventId) return null;
    return { eventId, flow };
  } catch {
    return null;
  }
}
