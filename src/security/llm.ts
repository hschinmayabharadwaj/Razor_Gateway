// LLM output validation / sanitization for the customer-facing seam.
//
// The LLM never makes a decision, but its output still reaches a customer
// (email / SMS / WhatsApp / voice script). That output is untrusted: a
// prompt-injected or malformed response could carry phishing-adjacent content,
// malicious / typo-squatted URLs, control characters, or leaked PII. This module
// is a last-line gate — reject-or-censor at the boundary before any copy is sent.

export interface LLMCopyInput {
  subject?: string;
  body?: string;
  channel?: string;
}

export interface LLMValidationResult {
  ok: boolean;
  reasons: string[];
  subject?: string;
  body?: string;
}

const INJECTION_PATTERNS: RegExp[] = [
  /\b(ignore (all )?previous instructions|ignore (the )?above|system prompt|you are now|as an ai|jailbreak|DAN\b)\b/i,
  /<\s*script\b/i,
  /<\s*iframe\b/i,
];

const SCHEMES = /^(https?:\/\/)/i;
const BLOCKED_HOSTS = /(^|[^a-z0-9-])(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])([:/]|$)/i;

function validateText(text: string | undefined, kind: string, reasons: string[]): void {
  if (!text) return;
  if (text.length > 600) { reasons.push(`${kind}_too_long`); return; }
  for (const p of INJECTION_PATTERNS) {
    if (p.test(text)) { reasons.push(`${kind}_injection_pattern`); return; }
  }
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
    reasons.push(`${kind}_control_chars`);
    return;
  }
  // URL safety: only allow http(s), never localhost/internal targets.
  const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  for (const u of urls) {
    if (!SCHEMES.test(u)) reasons.push(`${kind}_bad_scheme`);
    if (BLOCKED_HOSTS.test(u)) reasons.push(`${kind}_internal_url`);
  }
}

// Validate an LLM-produced message. On any finding, fail closed (do not send).
export function validateLLMCopy(input: LLMCopyInput): LLMValidationResult {
  const reasons: string[] = [];
  validateText(input.subject, 'subject', reasons);
  validateText(input.body, 'body', reasons);
  // Never allow a customer-facing message to contain a full PII pattern.
  if (input.body && /\+91 ?\d{10}|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i.test(input.body)) {
    reasons.push('body_leaks_pii');
  }
  return { ok: reasons.length === 0, reasons, subject: input.subject, body: input.body };
}

// Censor known-bad tokens when a soft-pass is acceptable (e.g. logs). Hard
// reject is the default for outbound customer copy.
export function censorLLMCopy(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, '[blocked]')
    .replace(/\bDAN\b/gi, '[blocked]')
    .replace(/\+91 ?\d{10}/g, '[redacted-phone]');
}
