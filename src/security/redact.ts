// PII redaction for log / exception-list views.
//
// The hash chain protects INTEGRITY, not CONFIDENTIALITY: audit entries carry
// customer IDs, invoice IDs, phone numbers and amounts in plaintext. Anyone with
// file access can read them. This module provides a field-level redaction layer
// so that any *read* surface (dashboard, exception list, auditor export) can
// hide PII fields unless the caller is authorized to see raw values.
//
// Redaction is intentionally conservative: it never reconstructs a masked value
// from the hash chain (that would defeat tamper-evidence), it only masks at
// presentation time.

export const PII_FIELDS = ['customerId', 'customerName', 'customerPhone', 'customerEmail'] as const;
export type PIIField = (typeof PII_FIELDS)[number];

const PHONE_LEN = 4;
const EMAIL_KEEP = 2;

function maskPhone(phone: string): string {
  return phone.length > PHONE_LEN ? phone.slice(0, 3) + '••••' + phone.slice(-2) : '••••';
}

function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at <= 0) return '•••@' + email.slice(at + 1);
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const shown = local.slice(0, EMAIL_KEEP);
  return `${shown}•••@${domain}`;
}

function maskName(name: string): string {
  if (!name) return '•••';
  const parts = name.split(/\s+/);
  return parts.map((p) => (p.length > 0 && parts.length > 1 ? p[0] + '•••' : p)).join(' ');
}

export function redactPII<T>(record: T, fields: readonly PIIField[] = PII_FIELDS): T {
  if (!record || typeof record !== 'object') return record;
  const out: Record<string, unknown> = { ...(record as Record<string, unknown>) };
  for (const f of fields) {
    const raw = out[f];
    if (typeof raw !== 'string') continue;
    if (f === 'customerPhone') out[f] = maskPhone(raw);
    else if (f === 'customerEmail') out[f] = maskEmail(raw);
    else if (f === 'customerName') out[f] = maskName(raw);
    else if (f === 'customerId') out[f] = `cust_•••${raw.slice(-4)}`;
  }
  return out as T;
}

// Redact a full array of audit entries.
export function redactAuditEntries<T>(entries: T[]): T[] {
  return entries.map((e) => redactPII(e));
}
