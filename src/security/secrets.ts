// Secrets management policy.
//
// RULE: no secret is ever hard-coded or committed. All secrets come from the
// environment (or a secrets manager injected at deploy time). This file is the
// single gate for reading them, so the policy is stated in one place and the
// test suite can prove we never fall back to a literal.
//
// In a real deployment these values would be supplied by the platform (env,
// Vault, KMS); this module just enforces the "read from env, fail fast if
// absent, never print" contract.

const REDACT = '********';

// Read a required secret. Throws if absent so a misconfigured deploy fails
// closed (never runs with a blank/default secret).
export function requireSecret(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Required secret '${name}' is not set (env only, never committed)`);
  return v;
}

// Read an optional secret; returns undefined if unset.
export function optionalSecret(name: string): string | undefined {
  return process.env[name];
}

// Stub for tests: a stable, obviously-non-secret key. NOT used in production
// paths — it exists only so unit tests can verify the crypto without a real
// secret. Production webhook verification ALWAYS goes through requireSecret.
export const TEST_ONLY_SECRET = 'webhook_secret_for_unit_tests_only';

export function redactSecret(value: string | undefined): string {
  if (!value || value.length === 0) return REDACT;
  if (value.length <= 8) return REDACT;
  return value.slice(0, 2) + '…' + value.slice(-2) + ' (len ' + value.length + ')';
}
