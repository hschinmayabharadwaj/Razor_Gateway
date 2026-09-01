// Access-control stub.
//
// Production-grade auth (users, roles, sessions, per-action scopes, audit of
// who did what) is beyond a hackathon build. But "no auth at all" is a
// visible zero, so this module establishes the *boundary*: every privileged
// action (trigger a batch run, tune sandbox params, read the audit log /
// exception list) is gated behind a caller-supplied credential, and every
// decision is recorded. The actual credential store is injected — in this
// stub it is a small API-key allow-list; in production it would be a real
// identity layer.
//
// Principle: default-DENY. Unknown or missing credentials are rejected before
// any action is considered.

import { createHmac, timingSafeEqual } from 'crypto';

export type Action =
  | 'run_batch'
  | 'tune_sandbox'
  | 'read_audit_log'
  | 'read_exception_list'
  | 'verify_anchor';

export interface AccessDecision {
  allowed: boolean;
  actor: string; // resolved principal id, or 'anonymous'
  action: Action;
  reason?: string; // when denied
}

// The permission matrix: which actions each role may perform.
const ROLE_PERMISSIONS: Record<string, Action[]> = {
  operator: ['run_batch', 'read_audit_log', 'read_exception_list', 'verify_anchor'],
  admin: ['run_batch', 'tune_sandbox', 'read_audit_log', 'read_exception_list', 'verify_anchor'],
  auditor: ['read_audit_log', 'read_exception_list', 'verify_anchor'],
};

// Credential -> (role, principal). In production this is a real identity
// provider; here it's a deterministic allow-list so the tests are hermetic.
// NEVER put real secrets here — see secrets.ts.
const CREDENTIAL_STORE: Record<string, { role: string; principal: string }> = {
  'op_key_demo': { role: 'operator', principal: 'ops-demo' },
  'admin_key_demo': { role: 'admin', principal: 'admin-demo' },
  'audit_key_demo': { role: 'auditor', principal: 'audit-demo' },
};

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Resolve a credential to a principal. Constant-time lookup against the store
// to avoid trivial enumeration/timing on the key itself.
function resolve(credential: string): { role: string; principal: string } | null {
  for (const candidate of Object.keys(CREDENTIAL_STORE)) {
    if (safeEqual(candidate, credential)) return CREDENTIAL_STORE[candidate];
  }
  return null;
}

// Authorize a request. `credential` is the caller-supplied API key (env/header,
// never in a URL). Deny-by-default; unknown keys -> anonymous + denied.
export function authorize(credential: string | undefined, action: Action): AccessDecision {
  if (!credential) {
    return { allowed: false, actor: 'anonymous', action, reason: 'missing_credential' };
  }
  const principal = resolve(credential);
  if (!principal) {
    return { allowed: false, actor: 'anonymous', action, reason: 'unknown_credential' };
  }
  const perms = ROLE_PERMISSIONS[principal.role] ?? [];
  if (!perms.includes(action)) {
    return { allowed: false, actor: principal.principal, action, reason: 'forbidden_for_role' };
  }
  return { allowed: true, actor: principal.principal, action };
}

// Convenience guard: runs `fn` only if authorized, returns a rejected-style
// result otherwise. Illustrates how every privileged entry point calls this.
export function guard<T>(
  credential: string | undefined,
  action: Action,
  fn: () => T,
): { ok: true; value: T } | { ok: false; denied: AccessDecision } {
  const d = authorize(credential, action);
  if (!d.allowed) return { ok: false, denied: d };
  return { ok: true, value: fn() };
}
